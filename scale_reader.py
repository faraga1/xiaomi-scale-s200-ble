"""
Active BLE GATT client for a Xiaomi Smart Scale S200 (MJTZC02YM).

See README.md for the full protocol writeup (login handshake, the
direct-vs-framed dual transfer form, the weight-record byte layout, and
how all of this was reverse-engineered). This docstring only summarizes.

This scale does not broadcast weight in its BLE advertisements at all --
confirmed by extensive live testing, every advertisement is an 11-byte
minimal MiBeacon frame with no object payload. The real weight is
delivered only over an authenticated, AES-CCM encrypted GATT session,
using Xiaomi's older "mi"/"mible" secure-login scheme (aka "miauth").

## Protocol summary

1. Connect, resolve the four relevant characteristics by UUID (see
   UUID_LOGIN/UUID_AUTH/UUID_CMD/UUID_PROP below -- NOT stable raw ATT
   handles, those differ per session for this device), enable
   notifications on all four.
2. miauth login:
     - write CMD_LOGIN (`24000000`) to the LOGIN characteristic
     - on the AUTH characteristic: send a 16-byte random `rand_key`,
       receive the scale's 16-byte `remote_key` and its 32-byte HMAC proof
       (`remote_info`), derive session keys, send our own 32-byte HMAC
       proof (`login_info`), wait for CFM_LOGIN_OK on the LOGIN
       characteristic.
     - session keys: HKDF-SHA256(ikm=XIAOMI_TOKEN,
       salt=rand_key+remote_key, info=b"mible-login-info", length=64) ->
       dev_key(16) | app_key(16) | dev_iv(4) | app_iv(4).
3. Send a small set of app->device commands over the CMD characteristic
   (AES-CCM encrypted with app_key/app_iv) that mirror what the official
   app sends right after login -- an "open session" (op 0xF0), a
   status/profile request, a user-profile push, and a property
   "subscribe" request. Empirically, the scale does not push
   weight-bearing records until after the subscribe request; small
   periodic "heartbeat" pushes happen anyway.
4. PROP characteristic notifications (AES-CCM encrypted with
   dev_key/dev_iv) are decrypted continuously. A per-message counter is
   read directly out of each notification's own (unencrypted) header --
   there is no need to track/predict it, the device tells us what it is
   every time.
5. Decrypted frames with op byte 0x07 are data-record pushes; the payload
   after the 0xa0 ASCII-string marker is a comma-separated record ending
   `...,<flag>,<unix_timestamp>`. The field immediately before that pair is
   the weight, in hundredths of a kilogram. `raw_value / 100 ==
   weight_kg`, confirmed exact against a real 89.75 kg ground-truth read.
"""

import asyncio
import hmac
import hashlib
import logging
import os
import struct
import time

import httpx
from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("scale-reader")

XIAOMI_MAC = os.environ["XIAOMI_MAC"].upper()  # scale's BLE MAC, e.g. AA:BB:CC:DD:EE:FF

# The GATT-login secret. This is the Xiaomi cloud "token" field (12 bytes /
# 24 hex chars) -- NOT the 16-byte bindkey/BLE KEY below, and NOT the same
# value. The bindkey fails the HMAC verification below; the 12-byte token
# passes it exactly. See README.md's "Two different secrets" section.
XIAOMI_TOKEN = bytes.fromhex(os.environ["XIAOMI_TOKEN"])
if len(XIAOMI_TOKEN) != 12:
    raise SystemExit(
        f"XIAOMI_TOKEN must be 12 bytes (24 hex chars) -- got {len(XIAOMI_TOKEN)} bytes. "
        "This is the Xiaomi cloud 'token' field, not the 16-byte 'beaconkey'/XIAOMI_BINDKEY."
    )

# The MiBeacon advertisement-encryption key. NOT used for weight (this
# scale doesn't broadcast it) -- kept for parity / a possible future
# MiBeacon-path addition on a sibling model.
XIAOMI_BINDKEY = os.environ.get("XIAOMI_BINDKEY")

# Optional: POST {"weight_kg": ...} here on every new reading. If unset,
# readings are only printed to stdout.
WEBHOOK_URL = os.environ.get("WEBHOOK_URL")

# User-profile fields the official app pushes to the scale right after
# login (used for the scale's own on-device body-composition math -- not
# needed for weight_kg itself). Defaults are the literal values observed
# in the original captures; override via env if they matter for your use.
XIAOMI_PROFILE_MEMBER_ID = os.environ.get("XIAOMI_PROFILE_MEMBER_ID", "1")
XIAOMI_PROFILE_AGE = int(os.environ.get("XIAOMI_PROFILE_AGE", "18"))
XIAOMI_PROFILE_SEX = int(os.environ.get("XIAOMI_PROFILE_SEX", "1"))  # 1 observed; meaning unconfirmed
XIAOMI_PROFILE_HEIGHT_CM = int(os.environ.get("XIAOMI_PROFILE_HEIGHT_CM", "170"))

# The property "subscribe" request's piid list. "1,2,3,4,5,6,7,8,9" is what
# the fullest of the two verified captures used, and it's the one that
# produced a full history dump; a later capture used just "10" and also
# produced weight pushes, so the exact list may not matter much -- kept
# configurable in case it turns out to gate which fields (e.g. body fat,
# impedance) get pushed alongside weight.
XIAOMI_SUBSCRIBE_PIIDS = os.environ.get("XIAOMI_SUBSCRIBE_PIIDS", "1,2,3,4,5,6,7,8,9")

# Debounce: the scale can push the same stable reading (or heartbeat-shaped
# junk) many times in a row. Only forward if it differs from the last one
# sent, or enough time has passed.
MIN_RESEND_INTERVAL_S = 30
last_sent_weight = None
last_sent_at = 0.0

# --- GATT characteristic UUIDs -----------------------------------------
# ATT *value handles* turned out NOT to be stable -- a different central
# connecting gets handed a completely different handle layout for the same
# characteristics. The UUIDs themselves are stable.
UUID_LOGIN = "00000010-0000-1000-8000-00805f9b34fb"  # CMD_LOGIN write target; also notifies CFM_LOGIN_OK
UUID_AUTH = "00000019-0000-1000-8000-00805f9b34fb"  # miauth key-exchange (rand_key/remote_key/remote_info/login_info)
UUID_CMD = "0000001a-0000-1000-8000-00805f9b34fb"  # app -> device encrypted commands (+ flow-control acks)
UUID_PROP = "0000001b-0000-1000-8000-00805f9b34fb"  # device -> app encrypted property/data pushes

CMD_LOGIN = bytes.fromhex("24000000")
RCV_RDY = bytes.fromhex("00000101")
RCV_OK = bytes.fromhex("00000100")
FRAME_ACK = bytes.fromhex("00000300")
CFM_LOGIN_OK = bytes.fromhex("21000000")

LOGIN_TIMEOUT_S = 15
COMMAND_TIMEOUT_S = 10
# If nothing at all arrives on the property channel for this long, assume
# the session is dead (the scale disconnects on its own after inactivity
# anyway) and force a reconnect rather than hanging forever.
PROP_IDLE_TIMEOUT_S = 300
# The scale only advertises/accepts connections when woken (e.g. by
# stepping on it). A weigh-in's awake window is short (observed ~10-30s),
# so once the scale IS reachable, keep retrying quickly rather than
# backing off far, or a real weigh-in could start and finish entirely
# between two connection attempts.
RECONNECT_BACKOFF_S = [2, 3, 5, 8, 10]  # last value repeats forever
# But while the scale is asleep (the overwhelmingly common case), constant
# fast re-scanning was observed live to keep the scale's display/radio
# powered on continuously, draining its battery for no benefit. Back off
# much further specifically for "not found".
ASLEEP_RETRY_S = 60


class ScaleAsleep(Exception):
    """Raised when the scale can't be found via scan -- distinguished from
    other failures so `main()` can back off far longer, since this means
    the scale is asleep, not that something went wrong mid weigh-in."""


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def aes_ccm_encrypt(key: bytes, iv: bytes, counter: int, plaintext: bytes) -> bytes:
    nonce = iv + b"\x00\x00\x00\x00" + struct.pack("<I", counter)
    return AESCCM(key, tag_length=4).encrypt(nonce, plaintext, None)


def aes_ccm_decrypt(key: bytes, iv: bytes, counter: int, ct_with_tag: bytes) -> bytes:
    nonce = iv + b"\x00\x00\x00\x00" + struct.pack("<I", counter)
    return AESCCM(key, tag_length=4).decrypt(nonce, ct_with_tag, None)


class ScaleSession:
    """One BLE connection's worth of state: notification queues, derived
    session keys, and outgoing-command bookkeeping. A fresh instance is
    created for every (re)connection -- nothing here is meant to survive
    a disconnect."""

    def __init__(self, client: BleakClient):
        self.client = client
        self.login_q: asyncio.Queue[bytes] = asyncio.Queue()
        self.auth_q: asyncio.Queue[bytes] = asyncio.Queue()
        self.cmd_q: asyncio.Queue[bytes] = asyncio.Queue()
        self.prop_q: asyncio.Queue[bytes] = asyncio.Queue()
        self.dev_key = self.app_key = self.dev_iv = self.app_iv = None
        self.out_counter = 0  # our own outgoing per-connection AES-CCM counter
        self.char_login = self.char_auth = self.char_cmd = self.char_prop = None

    def resolve_characteristics(self):
        """Look up the four characteristics by UUID. `client.services` is
        already populated by the time we're inside the `async with
        BleakClient(...)` block, so this needs no extra discovery call."""

        def get(uuid, role):
            char = self.client.services.get_characteristic(uuid)
            if char is None:
                raise RuntimeError(f"characteristic {uuid} ({role}) not found on this device -- GATT layout changed?")
            return char

        self.char_login = get(UUID_LOGIN, "LOGIN")
        self.char_auth = get(UUID_AUTH, "AUTH")
        self.char_cmd = get(UUID_CMD, "CMD")
        self.char_prop = get(UUID_PROP, "PROP")
        log.info(
            "resolved characteristics: LOGIN=handle%s AUTH=handle%s CMD=handle%s PROP=handle%s",
            self.char_login.handle, self.char_auth.handle, self.char_cmd.handle, self.char_prop.handle,
        )

    async def start_notifications(self):
        self.resolve_characteristics()

        def make_handler(queue):
            def handler(_char, data: bytearray):
                queue.put_nowait(bytes(data))

            return handler

        await self.client.start_notify(self.char_login, make_handler(self.login_q))
        await self.client.start_notify(self.char_auth, make_handler(self.auth_q))
        await self.client.start_notify(self.char_cmd, make_handler(self.cmd_q))
        await self.client.start_notify(self.char_prop, make_handler(self.prop_q))

    async def _recv_auth(self, expect_prefix: bytes | None = None) -> bytes:
        msg = await asyncio.wait_for(self.auth_q.get(), timeout=LOGIN_TIMEOUT_S)
        if expect_prefix is not None and not msg.startswith(expect_prefix):
            raise RuntimeError(f"unexpected AUTH message, wanted prefix {expect_prefix.hex()}, got {msg.hex()}")
        return msg

    async def _recv_tagged(self, tag: int, expect_len: int) -> bytes:
        """Receive a device-originated tagged value (remote_key, tag 0x0d;
        remote_info, tag 0x0c) on the AUTH characteristic, handling both
        the "direct" (`00 00 02 <tag>` + data) and "framed"/multi-parcel
        (`00 00 00 <tag> <parcel_count_le16>` header, then
        RCV_RDY/parcel/RCV_OK per parcel) transfer forms -- see README.md's
        "direct vs framed" section for why both exist."""
        msg = await asyncio.wait_for(self.auth_q.get(), timeout=LOGIN_TIMEOUT_S)

        direct_prefix = bytes([0x00, 0x00, 0x02, tag])
        framed_prefix = bytes([0x00, 0x00, 0x00, tag])

        if msg.startswith(direct_prefix):
            data = msg[4:]
        elif msg.startswith(framed_prefix):
            parcel_count = struct.unpack("<H", msg[4:6])[0]
            data = b""
            for _ in range(parcel_count):
                await self.client.write_gatt_char(self.char_auth, RCV_RDY, response=False)
                parcel = await asyncio.wait_for(self.auth_q.get(), timeout=LOGIN_TIMEOUT_S)
                data += parcel[2:]  # parcel format: <parcel_no_le16><data>
                await self.client.write_gatt_char(self.char_auth, RCV_OK, response=False)
        else:
            raise RuntimeError(
                f"unexpected AUTH message for tag 0x{tag:02x}, "
                f"wanted prefix {direct_prefix.hex()} or {framed_prefix.hex()}, got {msg.hex()}"
            )

        if len(data) != expect_len:
            raise RuntimeError(f"tag 0x{tag:02x} payload wrong length: got {len(data)}, wanted {expect_len}")
        return data

    async def recv_prop(self) -> tuple[int, bytes]:
        """Receive one device->app property push on the PROP characteristic
        and return (counter, ciphertext_with_tag). Like AUTH, this device
        delivers these in either the direct or framed form -- confirmed
        live, a framed push can show up here even after login succeeds."""
        msg = await self.prop_q.get()

        direct_prefix = bytes.fromhex("00000200")
        framed_prefix = bytes.fromhex("00000000")

        if msg.startswith(direct_prefix) and len(msg) >= 6:
            ctr = struct.unpack("<H", msg[4:6])[0]
            return ctr, msg[6:]
        elif msg.startswith(framed_prefix) and len(msg) >= 6:
            parcel_count = struct.unpack("<H", msg[4:6])[0]
            data = b""
            for _ in range(parcel_count):
                await self.client.write_gatt_char(self.char_prop, RCV_RDY, response=False)
                parcel = await self.prop_q.get()
                data += parcel[2:]
                await self.client.write_gatt_char(self.char_prop, RCV_OK, response=False)
            if len(data) < 2:
                raise RuntimeError(f"framed PROP push too short after reassembly: {data.hex()}")
            ctr = struct.unpack("<H", data[0:2])[0]
            return ctr, data[2:]
        else:
            raise RuntimeError(f"unrecognised PROP notification shape: {msg.hex()}")

    async def login(self):
        """Full miauth handshake. Raises on any protocol/crypto mismatch --
        the caller is expected to disconnect and retry on failure."""
        log.info("negotiated MTU: %s", getattr(self.client, "mtu_size", "unknown"))

        rand_key = os.urandom(16)

        await self.client.write_gatt_char(self.char_login, CMD_LOGIN, response=False)

        # -- send our rand_key --
        await self.client.write_gatt_char(self.char_auth, bytes.fromhex("0000000b0100"), response=False)
        await self._recv_auth(RCV_RDY)
        await self.client.write_gatt_char(self.char_auth, bytes.fromhex("0100") + rand_key, response=False)
        await self._recv_auth(RCV_OK)

        # -- receive the scale's remote_key + remote_info --
        remote_key = await self._recv_tagged(tag=0x0D, expect_len=16)
        await self.client.write_gatt_char(self.char_auth, FRAME_ACK, response=False)

        remote_info = await self._recv_tagged(tag=0x0C, expect_len=32)
        await self.client.write_gatt_char(self.char_auth, FRAME_ACK, response=False)

        # -- derive session keys and verify the device's proof BEFORE
        #    sending our own -- fail fast with a clear diagnostic if
        #    XIAOMI_TOKEN is wrong, rather than waiting for the device to
        #    reject us --
        salt = rand_key + remote_key
        k = hkdf_sha256(XIAOMI_TOKEN, salt, b"mible-login-info", 64)
        self.dev_key, self.app_key, self.dev_iv, self.app_iv = k[0:16], k[16:32], k[32:36], k[36:40]

        expected_remote_info = hmac.new(self.dev_key, remote_key + rand_key, hashlib.sha256).digest()
        if expected_remote_info != remote_info:
            raise RuntimeError(
                "remote_info HMAC mismatch -- XIAOMI_TOKEN is very likely wrong "
                "(this must be the Xiaomi cloud 'token' field, not the bindkey/beaconkey)"
            )

        login_info = hmac.new(self.app_key, salt, hashlib.sha256).digest()

        # -- send our login_info proof --
        await self.client.write_gatt_char(self.char_auth, bytes.fromhex("0000000a0100"), response=False)
        await self._recv_auth(RCV_RDY)
        await self.client.write_gatt_char(self.char_auth, bytes.fromhex("0100") + login_info, response=False)
        await self._recv_auth(RCV_OK)

        confirm = await asyncio.wait_for(self.login_q.get(), timeout=LOGIN_TIMEOUT_S)
        if confirm != CFM_LOGIN_OK:
            raise RuntimeError(f"login not confirmed, device replied {confirm.hex()} (expected {CFM_LOGIN_OK.hex()})")

        log.info("miauth login OK")

    async def send_command(self, plaintext: bytes):
        """Encrypt `plaintext` with app_key/app_iv at the next outgoing
        counter value and push it through the single-parcel framed-write
        procedure on the CMD characteristic. Every command observed in
        the original captures fit in one parcel; this does not implement
        multi-parcel framing for outgoing writes."""
        ciphertext = aes_ccm_encrypt(self.app_key, self.app_iv, self.out_counter, plaintext)
        chunk = struct.pack("<H", self.out_counter) + ciphertext
        if len(chunk) > 244:  # ATT_MTU(251) - 3 (ATT header) - 2 (parcel_no), rough safety margin
            raise RuntimeError(f"command too large for single-parcel framing ({len(chunk)} bytes)")
        self.out_counter += 1

        # header: 00 00 00 00 <parcel_count_le16=1>
        await self.client.write_gatt_char(self.char_cmd, bytes.fromhex("000000000100"), response=False)
        await asyncio.wait_for(self.cmd_q.get(), timeout=COMMAND_TIMEOUT_S)  # RCV_RDY
        parcel = bytes.fromhex("0100") + chunk  # parcel_no=1 (always -- single parcel)
        await self.client.write_gatt_char(self.char_cmd, parcel, response=False)
        await asyncio.wait_for(self.cmd_q.get(), timeout=COMMAND_TIMEOUT_S)  # RCV_OK

    async def ack_prop(self):
        await self.client.write_gatt_char(self.char_prop, FRAME_ACK, response=False)

    def next_tid(self) -> int:
        # Reuses the outgoing AES-CCM counter as the tid too -- both
        # captures showed the app's tid simply incrementing per command,
        # same as its own counter; no evidence it needs to be independent.
        return self.out_counter + 1


async def send_open_session(session: ScaleSession):
    """op 0xF0 -- observed as the very first command in both captures,
    immediately after login. 5-byte plaintext: [len=05][0x20][tid_le16][0xf0]."""
    tid = session.next_tid()
    plaintext = bytes([0x05, 0x20]) + struct.pack("<H", tid) + bytes([0xF0])
    await session.send_command(plaintext)


async def send_status_probe(session: ScaleSession):
    """A small fixed op=0x05/sub=0x06 request seen right before the
    subscribe request in both captures. Purpose not fully decoded;
    replicated because both real sessions sent it and it's cheap/harmless."""
    tid = session.next_tid()
    plaintext = bytes([0x08, 0x20]) + struct.pack("<H", tid) + bytes([0x05, 0x06, 0x01, 0x00])
    await session.send_command(plaintext)


async def send_profile(session: ScaleSession):
    """User-profile JSON push (op=0x05/sub=0x07), replicated verbatim from
    the captures with configurable personal fields."""
    tid = session.next_tid()
    payload = (
        '{"mid":"%s","duid":1,"uc":1,"ow":1,"unit":1,"time":%d,'
        '"ud":[{"duid":1,"ut":1,"age":%d,"sex":%d,"hi":%d,"wt":0}]}'
        % (
            XIAOMI_PROFILE_MEMBER_ID,
            int(time.time()),
            XIAOMI_PROFILE_AGE,
            XIAOMI_PROFILE_SEX,
            XIAOMI_PROFILE_HEIGHT_CM,
        )
    ).encode("ascii")
    header = bytes([0x20]) + struct.pack("<H", tid) + bytes([0x05, 0x07, 0x01, 0x01, 0x01, 0x00, len(payload), 0xA0])
    body = header + payload
    plaintext = bytes([len(body) + 1]) + body
    await session.send_command(plaintext)


async def send_subscribe(session: ScaleSession):
    """Property subscribe request (op=0x05/sub=0x06) -- the command that,
    empirically across both captures, precedes the scale actually pushing
    weight-bearing (op=0x07) records rather than just heartbeats."""
    tid = session.next_tid()
    piids = XIAOMI_SUBSCRIBE_PIIDS.encode("ascii")
    header = bytes([0x20]) + struct.pack("<H", tid) + bytes([0x05, 0x06, 0x02, 0x01, 0x02, 0x00, len(piids), 0xA0])
    body = header + piids
    plaintext = bytes([len(body) + 1]) + body
    await session.send_command(plaintext)


def try_extract_weight_kg(plaintext: bytes) -> float | None:
    """Decode a weight reading out of a decrypted PROP-characteristic
    payload, if it's one of the op=0x07 ASCII data records. Returns None
    (never raises) for anything else -- heartbeats, device-info pushes,
    acks.

    Record shape, byte-verified against a real 89.75 kg ground-truth
    reading: `[len][0x20][tid_le16][0x07][sub][...][strlen][0xa0]<ascii>`,
    where <ascii> is a comma-separated record ending `...,<flag>,<unix_ts>`.
    The field immediately before that trailing pair is the weight in
    hundredths of a kilogram.
    """
    if len(plaintext) < 6 or plaintext[4] != 0x07:
        return None

    marker = plaintext.find(b"\xa0")
    if marker == -1 or marker + 1 >= len(plaintext):
        return None

    try:
        text = plaintext[marker + 1 :].decode("ascii")
    except UnicodeDecodeError:
        return None

    fields = text.split(",")
    if len(fields) < 3:
        return None

    weight_field, flag_field, ts_field = fields[-3], fields[-2], fields[-1]
    if not (weight_field.isdigit() and flag_field.isdigit() and ts_field.isdigit()):
        return None

    weight_kg = int(weight_field) / 100.0
    if not (1.0 <= weight_kg <= 300.0):  # sanity bound, reject obvious garbage
        return None
    return weight_kg


async def emit_reading(weight_kg: float):
    global last_sent_weight, last_sent_at
    now = time.monotonic()
    log.info("weight_kg=%.2f", weight_kg)
    if weight_kg == last_sent_weight and now - last_sent_at < MIN_RESEND_INTERVAL_S:
        return
    last_sent_weight = weight_kg
    last_sent_at = now

    if not WEBHOOK_URL:
        return
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.post(WEBHOOK_URL, json={"weight_kg": weight_kg})
            resp.raise_for_status()
            log.info("posted reading to %s", WEBHOOK_URL)
        except httpx.HTTPError as err:
            log.error("failed to POST reading to %s: %s", WEBHOOK_URL, err)


async def run_session_once():
    """Connect, log in, subscribe, and stream property pushes until
    disconnected or idle for too long. Raises on any failure -- the caller
    handles retry/backoff."""
    disconnected = asyncio.Event()

    def on_disconnect(_client):
        log.warning("BLE disconnected")
        disconnected.set()

    # BlueZ (via bleak) can't reliably connect by bare address string alone
    # if it hasn't already seen the device on this bluetoothd instance --
    # find_device_by_address() runs a real scan and returns a BLEDevice
    # bleak can connect to directly.
    device = await BleakScanner.find_device_by_address(XIAOMI_MAC, timeout=10)
    if device is None:
        raise ScaleAsleep(f"could not find {XIAOMI_MAC} via scan")

    async with BleakClient(device, disconnected_callback=on_disconnect, timeout=20) as client:
        # bleak's BlueZ backend defaults to the bare-minimum ATT_MTU (23)
        # unless _acquire_mtu() is called and succeeds -- on some bleak
        # versions that method doesn't even exist. Treat a larger MTU as
        # a nice-to-have: the framed multi-parcel path in _recv_tagged()/
        # recv_prop() works regardless. See README.md's "the MTU trap".
        try:
            await client._acquire_mtu()
        except Exception as err:
            log.warning(
                "failed to acquire a larger MTU (%s), staying at the default (23) -- "
                "relying on multi-parcel framed receive/send instead",
                err,
            )

        session = ScaleSession(client)
        await session.start_notifications()
        await session.login()

        await send_open_session(session)
        await send_status_probe(session)
        await send_profile(session)
        await send_subscribe(session)
        log.info("subscribed, waiting for property pushes")

        while not disconnected.is_set():
            get_prop = asyncio.ensure_future(session.recv_prop())
            wait_disc = asyncio.ensure_future(disconnected.wait())
            done, pending = await asyncio.wait(
                {get_prop, wait_disc}, timeout=PROP_IDLE_TIMEOUT_S, return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
            if not done:
                raise TimeoutError(f"no property push received in {PROP_IDLE_TIMEOUT_S}s, assuming session is dead")
            if wait_disc in done:
                break

            ctr, ct = get_prop.result()
            try:
                plaintext = aes_ccm_decrypt(session.dev_key, session.dev_iv, ctr, ct)
            except InvalidTag:
                log.warning("failed to decrypt property push (bad CCM tag), skipping: ctr=%d len=%d", ctr, len(ct))
                await session.ack_prop()
                continue
            except Exception:
                log.exception("unexpected error decrypting property push, skipping")
                await session.ack_prop()
                continue

            await session.ack_prop()

            try:
                weight_kg = try_extract_weight_kg(plaintext)
            except Exception:
                log.exception("unexpected error parsing decrypted payload %s, skipping", plaintext.hex())
                continue

            if weight_kg is not None:
                await emit_reading(weight_kg)


async def main():
    log.info("Starting active GATT client for %s", XIAOMI_MAC)
    backoff_idx = 0
    while True:
        try:
            await run_session_once()
            backoff_idx = 0  # a clean run (even if it ended via disconnect) resets backoff
            delay = RECONNECT_BACKOFF_S[0]
        except ScaleAsleep as err:
            log.info("%s -- scale is asleep, retrying in %ds", err, ASLEEP_RETRY_S)
            backoff_idx = 0  # don't ramp the awake-retry backoff while asleep
            delay = ASLEEP_RETRY_S
        except (BleakError, asyncio.TimeoutError, TimeoutError, RuntimeError, OSError) as err:
            log.error("session failed: %s", err)
            delay = RECONNECT_BACKOFF_S[min(backoff_idx, len(RECONNECT_BACKOFF_S) - 1)]
            backoff_idx += 1
        except Exception:
            log.exception("unexpected error in scale session")
            delay = RECONNECT_BACKOFF_S[min(backoff_idx, len(RECONNECT_BACKOFF_S) - 1)]
            backoff_idx += 1

        log.info("reconnecting in %ds", delay)
        await asyncio.sleep(delay)


if __name__ == "__main__":
    asyncio.run(main())
