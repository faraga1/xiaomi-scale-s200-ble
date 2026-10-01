"""
Sync client for the Xiaomi Smart Scale S200 (MiBeacon product id 0x4dcb).

Collects every weigh-in from the scale over Bluetooth LE -- no Xiaomi Home
app, no cloud -- and hands each one (weight plus the scale's own timestamp)
to a webhook, or prints it as a JSON line. README.md is the full protocol
reference; this docstring is the short version the code is written against.

## How the scale behaves, and why this client is shaped around it

- The scale is asleep almost all the time: not advertising, not
  connectable. Stepping on it wakes it up; it advertises (~every 0.5s)
  for a while and then goes back to sleep. A BLE connection counts as
  activity and keeps it awake -- so a client that connects whenever it can
  see the scale never lets it sleep. (An earlier version of this client
  did exactly that; the display kept flickering on and off until the
  batteries were pulled.)
- The scale keeps every weigh-in in its own memory, with its own unix
  timestamp, until a client deletes it. Catching a weigh-in live is a
  nice-to-have, not a requirement: any later connection can collect it.

So this client never connects on a timer, and never just because the
scale is advertising. It only scans (observing advertisements doesn't wake
anything up), and connects when an advertisement says there's something
new:

  1. the MiBeacon frame counter in the advertisement (byte 4 of the 0xfe95
     service data) differs from what it was after the last sync. It goes
     up by one for every weigh-in the scale puts in its memory, so a
     weigh-in shows up a few seconds after it's finished. (Also: the first
     sighting after starting, and a daily safety sync.)
  2. connect, log in, set the scale's clock, fetch all stored weigh-ins,
     deliver them with their own timestamps, delete them from the scale,
     then collect weigh-ins live while someone is using it, and disconnect
     as soon as it's quiet (a connection keeps the scale awake, and it
     falls asleep within seconds of the disconnect)
  3. remember the counter, and don't connect again until it moves on.

The scale merely appearing is NOT a reason to connect. An earlier version
treated a 10s scan window without the scale as "asleep" and the next
sighting as "woke up, sync". At a weak signal (-80 dBm) advertisements go
missing for 10s at a time while the scale is awake; every such gap meant a
connection, which kept the scale awake -- about 20 connections in 20
minutes, without a single weigh-in.

Counter facts: +1 for every stored weigh-in (4 of 4 observed); a weigh-in
a client claims live doesn't count; it restarts at 0 when the batteries go
in. It was also seen going up without a stored weigh-in (+4 in 3 hours), so
something else moves it too. Such a change costs one fruitless sync, and a
counter that keeps moving like that gets ignored for an hour.

The scale also advertises while idle, at least some of the time. Another
S200 owner (github.com/kfirmaymon84/esp32-mirror-weight-tracker) found the
MiBeacon frame control -- the first two bytes of the service data -- flips
from 0x5830 when idle to 0x5b10 (bit 9 set) when someone steps on. The unit
this was developed on showed 0x5910 in phone captures. Not used for any
decision here: every change of frame control or counter is logged
("advertisement changed"), to learn the pattern first.

## Protocol

Decoded from HCI snoop captures of the Xiaomi Home app (decode_btsnoop.py
replays a capture through this file's own code).

Transport -- GATT service 0xfe95, characteristics by UUID16 (ATT handles
differ between clients, so never hardcode those):
  LOGIN 0x0010, AUTH 0x0019, CMD 0x001a (app->scale), PROP 0x001b
  (scale->app). Values on AUTH/CMD/PROP use a small framing layer:
    `00 00 02 <tag> <data>`   whole value in one write/notification
                              ("direct"); receiver answers `00 00 03 00`
    `00 00 00 <tag> <n_le16>` announces an n-parcel value ("framed");
                              receiver answers `00 00 01 01` (ready) once,
                              sender sends all n `<parcel_no_le16><chunk>`
                              back to back, receiver answers `00 00 01 00`
                              (received) once
  The scale sends direct when a value fits in one write and framed when it
  doesn't -- e.g. a long list of stored weigh-ins. The app, and this
  client, always send framed.

Pre-login payload-size probe: write `a4` to LOGIN; the scale sends
`00 00 04 00` + 2 bytes, then `00 00 04 01` + N bytes of 0xf2 on AUTH;
echo each back with 04 -> 05. The big probe's length is the largest value
the scale accepts in one write, and what it uses to decide direct vs
framed. Skip the probe and it assumes 20 bytes: everything goes framed.

miauth login: write `24000000` to LOGIN; send rand_key (16 random bytes,
tag 0x0b); receive remote_key (16 bytes, tag 0x0d) and remote_info (tag
0x0c); HKDF-SHA256(ikm=XIAOMI_TOKEN, salt=rand_key+remote_key,
info="mible-login-info", 64 bytes) -> dev_key|app_key|dev_iv|app_iv;
remote_info must equal HMAC-SHA256(dev_key, remote_key+rand_key); send
HMAC-SHA256(app_key, rand_key+remote_key) (tag 0x0a); LOGIN notifies
`21000000`.

After login, CMD and PROP values are `<ctr_le16><AES-CCM ciphertext with
4-byte tag>`, nonce = iv + 00000000 + ctr_le32 (app_key/app_iv towards
the scale, dev_key/dev_iv from it). Plaintexts are Xiaomi MIoT-spec
operations:
  `<u16: 0x2000 | total_len><u16 tid><op>` + body
    op 0xf0  hello; no body, the scale echoes it with the same tid
    op 0x05  action   `<siid><aiid><n>` + n params
    op 0x06  result   `<u16 status>[<n> + n params]`, same tid as the action
    op 0x07  event    `<siid><eiid><00><n>` + n params, sent by the scale
  param: `<u16 piid><u16 type << 12 | len><value>`; types seen:
  0x1 u8, 0x3 u16, 0x8 u64, 0xa string.

Services used:
  action 7.1  set user profile. p1 = JSON: member id, the scale's clock
              ("time"), and one user's age/sex/height and reference weight
              ("wt", 1/100 kg -- the scale uses it to recognise who stepped
              on). Result p2 = number of stored weigh-ins. The app sends
              this first on every connection.
  action 6.1  fetch stored weigh-ins. Result p3 = count; if non-zero the
              scale then sends event 6.1, p1 = records joined by "_", each
              `no,member_id,user_type,weight,flag,unix_ts` (weight in
              1/100 kg, ts in UTC, flag 0 = recognised user, 2 = not).
  action 6.2  delete stored weigh-ins, p2 = comma-separated record numbers.
  event 5.3   live weight while someone stands on the scale: p2 = stable
              (0/1), p3 = weight (u16, 1/100 kg).
  event 5.4   finished weigh-in, p4 = `member_id,user_type,weight,flag,ts`.
  action 4.3  claim a finished weigh-in for a member: p1 = member id (u64),
              p2 = 1, p8 = weight (u16). The app does this after every 5.4;
              claimed weigh-ins never showed up in a later fetch.
No body-composition values (impedance etc.) appear anywhere in the
captured traffic -- as far as the protocol shows, this scale only weighs.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx
from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("s200")
log.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())
logging.getLogger("httpx").setLevel(logging.WARNING)  # one line per POST otherwise

# --- Configuration ----------------------------------------------------------
# Read without failing at import time so decode_btsnoop.py and the tests can
# import this module; main() refuses to start if the required ones are unset.

XIAOMI_MAC = os.environ.get("XIAOMI_MAC", "").upper()  # the scale's, e.g. AA:BB:CC:DD:EE:FF
# Where to deliver weigh-ins: POSTed as JSON {"weight_kg": 80.25,
# "recorded_at": "2026-09-30T07:15:42Z"}, with "Authorization: Bearer
# <WEBHOOK_TOKEN>" if that's set. Unset: one JSON line per weigh-in on
# stdout. Either way a weigh-in only counts as delivered (and gets deleted
# from the scale) once that succeeded. The same weigh-in can be delivered
# twice (e.g. a retried sync); dedupe on recorded_at + weight_kg.
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")
WEBHOOK_TOKEN = os.environ.get("WEBHOOK_TOKEN", "")
# Leave weigh-ins in the scale's memory (don't delete or claim them), e.g.
# to keep using the Xiaomi Home app alongside this. They're then delivered
# again on every sync, and the scale keeps waking up to offer them.
KEEP_ON_SCALE = os.environ.get("KEEP_ON_SCALE", "") not in ("", "0", "false")

# The miauth login secret: the "TOKEN" field from Xiaomi-cloud-tokens-
# extractor (12 bytes / 24 hex chars), NOT its "BLE KEY"/bindkey field.
try:
    XIAOMI_TOKEN = bytes.fromhex(os.environ.get("XIAOMI_TOKEN", ""))
except ValueError:
    XIAOMI_TOKEN = b""

# The user profile sent to the scale on every connection (action 7.1). It
# only affects the scale's own display and which member it attributes a
# weigh-in to; every weigh-in gets delivered regardless. If you also use the
# Xiaomi Home app, use your account's member id (the "mid" in the app's own
# profile push -- decode_btsnoop.py shows it) so the two don't fight over
# the scale's user list; otherwise any number works as far as observed.
PROFILE_MEMBER_ID = int(os.environ.get("XIAOMI_PROFILE_MEMBER_ID", "1"))
PROFILE_AGE = int(os.environ.get("XIAOMI_PROFILE_AGE", "18"))
PROFILE_SEX = int(os.environ.get("XIAOMI_PROFILE_SEX", "1"))
PROFILE_HEIGHT_CM = int(os.environ.get("XIAOMI_PROFILE_HEIGHT_CM", "170"))
# Starting reference weight; replaced by the latest weigh-in once there is one.
PROFILE_WEIGHT_KG = float(os.environ.get("XIAOMI_PROFILE_WEIGHT_KG", "80"))

# --- Timing -------------------------------------------------------------------

# One discovery window: find_scale() returns as soon as the scale is seen,
# or after this long if it isn't.
SCAN_WINDOW_S = 10
# While the scale is advertising: how long between checks of its MiBeacon
# counter. Short, because without a connection the scale can fall asleep
# ~15s after a weigh-in; checking doesn't connect.
AWAKE_RECHECK_S = 2
# Only for the log: how long the scale has to be unseen before that's
# logged as "not advertising". (Not used for any decision -- at a weak
# signal, gaps of 10s+ happen while the scale is awake.)
PRESENCE_GAP_S = 60
# Scan failures in a row (SCAN_RETRY_S apart) before exiting, so whatever
# supervises this process (Docker, systemd) can restart it; see main().
SCAN_RETRY_S = 5
MAX_SCAN_FAILURES = 12
# Safety net for anything the counter might not show: if the scale is
# advertising and the last sync was this long ago, sync anyway.
RESYNC_AFTER_S = 24 * 3600
# After a sync that failed outright (e.g. a bad link): wait before trying
# again, doubling per consecutive failure. The weigh-ins stay on the scale.
FAILED_SYNC_BACKOFF_S = 60
FAILED_SYNC_BACKOFF_MAX_S = 1800
# Counter changes that brought nothing new: after this many within
# FRUITLESS_WINDOW_S, ignore the counter for that long.
MAX_FRUITLESS_SYNCS = 3
FRUITLESS_WINDOW_S = 3600
# Connection attempts per wake-up. Logins used to stall about half the
# time (see ScaleLink.setup()); a failed attempt only costs a few seconds.
SYNC_ATTEMPTS = 4
STEP_TIMEOUT_S = 4  # any single reply in the login/framing layer
RESULT_TIMEOUT_S = 6  # the result of an action
RECORDS_TIMEOUT_S = 8  # the stored weigh-ins, after "fetch" reported a count
# After syncing stored weigh-ins: how long to wait for someone to be on the
# scale (live weight updates) before disconnecting, and once someone is, how
# long it has to be quiet again. Kept short because the connection is what
# keeps the scale awake -- it falls asleep within seconds of a disconnect.
# A step-on after the disconnect is still caught: the weigh-in gets stored,
# which the MiBeacon counter shows (see main()), or at the next wake-up.
LIVE_START_S = 5
LIVE_IDLE_S = 15
LIVE_MAX_S = 600

# Scale timestamps before this are the scale's clock not being set yet
# (e.g. fresh batteries, before the first profile push sets it) and get
# replaced by the current time. The S200 is newer than this.
MIN_PLAUSIBLE_TS = 1704067200  # 2024-01-01

# --- Crypto -------------------------------------------------------------------


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


def derive_session_keys(token: bytes, rand_key: bytes, remote_key: bytes) -> dict:
    k = hkdf_sha256(token, rand_key + remote_key, b"mible-login-info", 64)
    return {"dev_key": k[0:16], "app_key": k[16:32], "dev_iv": k[32:36], "app_iv": k[36:40]}


def aes_ccm_encrypt(key: bytes, iv: bytes, counter: int, plaintext: bytes) -> bytes:
    nonce = iv + b"\x00\x00\x00\x00" + struct.pack("<I", counter)
    return AESCCM(key, tag_length=4).encrypt(nonce, plaintext, None)


def aes_ccm_decrypt(key: bytes, iv: bytes, counter: int, ct_with_tag: bytes) -> bytes:
    nonce = iv + b"\x00\x00\x00\x00" + struct.pack("<I", counter)
    return AESCCM(key, tag_length=4).decrypt(nonce, ct_with_tag, None)


# --- MIoT message codec -------------------------------------------------------

OP_ACTION = 0x05
OP_RESULT = 0x06
OP_EVENT = 0x07
OP_HELLO = 0xF0

T_U8 = 0x1
T_U16 = 0x3
T_U64 = 0x8
T_STR = 0xA
_INT_SIZES = {T_U8: 1, T_U16: 2, T_U64: 8}


class ProtocolError(Exception):
    pass


def param(piid: int, ptype: int, value) -> bytes:
    raw = value.encode("ascii") if ptype == T_STR else int(value).to_bytes(_INT_SIZES[ptype], "little")
    return struct.pack("<HH", piid, ptype << 12 | len(raw)) + raw


def decode_params(buf: bytes, count: int) -> dict:
    params = {}
    pos = 0
    for _ in range(count):
        if pos + 4 > len(buf):
            raise ProtocolError(f"truncated parameter list: {buf.hex()}")
        piid, type_len = struct.unpack_from("<HH", buf, pos)
        ptype, length = type_len >> 12, type_len & 0xFFF
        raw = buf[pos + 4 : pos + 4 + length]
        if len(raw) != length:
            raise ProtocolError(f"truncated parameter {piid}: {buf.hex()}")
        pos += 4 + length
        if ptype == T_STR:
            params[piid] = raw.decode("ascii", "replace")
        elif length in (1, 2, 4, 8):
            params[piid] = int.from_bytes(raw, "little")
        else:
            params[piid] = raw
    return params


@dataclass
class Message:
    tid: int
    op: int
    siid: int = 0
    iid: int = 0  # aiid for actions, eiid for events
    status: int = 0
    params: dict = field(default_factory=dict)

    def __str__(self):
        if self.op == OP_HELLO:
            return f"hello tid={self.tid}"
        if self.op == OP_RESULT:
            return f"result tid={self.tid} status={self.status:#x} {self.params}"
        kind = {OP_ACTION: "action", OP_EVENT: "event"}.get(self.op, f"op{self.op:#x}")
        return f"{kind} {self.siid}.{self.iid} tid={self.tid} {self.params}"


def encode_message(tid: int, op: int, body: bytes = b"") -> bytes:
    return struct.pack("<HHB", 0x2000 | (5 + len(body)), tid, op) + body


def encode_action(tid: int, siid: int, aiid: int, *params: bytes) -> bytes:
    return encode_message(tid, OP_ACTION, bytes([siid, aiid, len(params)]) + b"".join(params))


def decode_message(pt: bytes) -> Message:
    if len(pt) < 5:
        raise ProtocolError(f"message too short: {pt.hex()}")
    _, tid, op = struct.unpack_from("<HHB", pt)
    body = pt[5:]
    msg = Message(tid, op)
    if op == OP_RESULT:
        msg.status = struct.unpack_from("<H", body)[0]
        if len(body) > 2:
            msg.params = decode_params(body[3:], body[2])
    elif op == OP_EVENT:
        msg.siid, msg.iid = body[0], body[1]
        msg.params = decode_params(body[4:], body[3])
    elif op == OP_ACTION:
        msg.siid, msg.iid = body[0], body[1]
        msg.params = decode_params(body[3:], body[2])
    return msg


@dataclass
class WeighIn:
    weight_kg: float
    timestamp: int
    record_no: int | None = None  # set for stored weigh-ins (needed to delete them)


def parse_weigh_in(text: str, numbered: bool) -> WeighIn | None:
    """Parse one `[no,]member_id,user_type,weight,flag,ts` record."""
    fields = text.split(",")
    if len(fields) != (6 if numbered else 5) or not all(f.isdigit() for f in fields):
        return None
    no = int(fields[0]) if numbered else None
    weight, ts = int(fields[-3]), int(fields[-1])
    return WeighIn(weight / 100, ts, no)


def parse_stored_records(text: str) -> list[WeighIn]:
    records = []
    for part in filter(None, text.split("_")):
        record = parse_weigh_in(part, numbered=True)
        if record is None:
            log.warning("unparseable stored weigh-in %r", part)
        else:
            records.append(record)
    return records


# --- Transport + session ------------------------------------------------------

UUIDS = {
    "LOGIN": "00000010-0000-1000-8000-00805f9b34fb",
    "AUTH": "00000019-0000-1000-8000-00805f9b34fb",
    "CMD": "0000001a-0000-1000-8000-00805f9b34fb",
    "PROP": "0000001b-0000-1000-8000-00805f9b34fb",
}
MIBEACON_UUID = "0000fe95-0000-1000-8000-00805f9b34fb"

CMD_LOGIN = bytes.fromhex("24000000")
LOGIN_OK = bytes.fromhex("21000000")
RCV_RDY = bytes.fromhex("00000101")
RCV_OK = bytes.fromhex("00000100")
RCV_ACK = bytes.fromhex("00000300")

TAG_DATA = 0x00
TAG_LOGIN_INFO = 0x0A
TAG_RAND_KEY = 0x0B
TAG_REMOTE_INFO = 0x0C
TAG_REMOTE_KEY = 0x0D


class Disconnected(Exception):
    pass


class ScaleLink:
    """One connection: framing layer, login, encrypted request/response."""

    def __init__(self):
        self.client = None
        self.chars = {}
        self.queues = {name: asyncio.Queue() for name in UUIDS}
        # Largest value the scale accepts in one write. Replaced by the MTU
        # probe's answer; 20 is what fits in the BLE default ATT_MTU of 23.
        self.max_value = 20
        self.keys = None
        self.connected = True
        self.out_ctr = 0
        self.tid = 0
        self.pending: dict[int, asyncio.Future] = {}
        self.stored_events: asyncio.Queue = asyncio.Queue()
        self.live_events: asyncio.Queue = asyncio.Queue()

    def on_disconnect(self, _client=None):
        self.connected = False
        # Wake everything that's waiting, so nothing sits out its timeout.
        for q in (*self.queues.values(), self.stored_events, self.live_events):
            q.put_nowait(None)
        for fut in self.pending.values():
            if not fut.done():
                fut.set_exception(Disconnected("scale disconnected"))

    def _notify_handler(self, name):
        def handler(_char, data: bytearray):
            log.debug("<- %s %s", name, bytes(data).hex())
            self.queues[name].put_nowait(bytes(data))

        return handler

    async def _get(self, name, forever=False) -> bytes:
        try:
            item = await asyncio.wait_for(self.queues[name].get(), None if forever else STEP_TIMEOUT_S)
        except asyncio.TimeoutError:
            raise ProtocolError(f"no reply on {name} within {STEP_TIMEOUT_S}s") from None
        if item is None:
            raise Disconnected("scale disconnected")
        return item

    async def _write(self, name, data: bytes):
        log.debug("-> %s %s", name, data.hex())
        await self.client.write_gatt_char(self.chars[name], data, response=False)

    async def _expect(self, name, want: bytes):
        got = await self._get(name)
        if got != want:
            raise ProtocolError(f"{name}: expected {want.hex()}, got {got.hex()}")

    async def send_value(self, name, tag: int, data: bytes):
        chunk = self.max_value - 2
        parcels = [data[i : i + chunk] for i in range(0, len(data), chunk)]
        await self._write(name, bytes([0, 0, 0, tag]) + struct.pack("<H", len(parcels)))
        await self._expect(name, RCV_RDY)
        for no, part in enumerate(parcels, 1):
            await self._write(name, struct.pack("<H", no) + part)
        await self._expect(name, RCV_OK)

    async def recv_value(self, name, first: bytes | None = None) -> tuple[int, bytes]:
        msg = first if first is not None else await self._get(name)
        if len(msg) >= 4 and msg[:3] == b"\x00\x00\x02":
            await self._write(name, RCV_ACK)
            return msg[3], msg[4:]
        if len(msg) == 6 and msg[:3] == b"\x00\x00\x00":
            count = struct.unpack("<H", msg[4:6])[0]
            await self._write(name, RCV_RDY)
            parcels = {}
            while len(parcels) < count:
                parcel = await self._get(name)
                parcels[struct.unpack("<H", parcel[:2])[0]] = parcel[2:]
            await self._write(name, RCV_OK)
            return msg[3], b"".join(parcels[no] for no in sorted(parcels))
        raise ProtocolError(f"{name}: unexpected value {msg.hex()}")

    async def setup(self):
        for name, uuid in UUIDS.items():
            char = self.client.services.get_characteristic(uuid)
            if char is None:
                raise ProtocolError(f"characteristic {name} ({uuid}) not found")
            self.chars[name] = char
        try:
            # Only affects bleak's own mtu_size bookkeeping; BlueZ negotiates
            # the real ATT_MTU (251 with this scale) by itself on connect.
            await self.client._backend._acquire_mtu()
        except Exception as err:
            log.debug("could not acquire MTU: %s", err)

        # Same order as the Xiaomi app: LOGIN notifications only get enabled
        # after the MTU probe, and there's a pause before the login starts.
        # The previous version enabled all four up front and sent the login
        # right on the heels of the probe echo; ~57% of its logins then got
        # no answer at all (119 of 210 sessions on 2026-09-20).
        for name in ("AUTH", "CMD", "PROP"):
            await self.client.start_notify(self.chars[name], self._notify_handler(name))

        await self._write("LOGIN", b"\xa4")
        small = await self._get("AUTH")
        if small[:4] != bytes.fromhex("00000400"):
            raise ProtocolError(f"unexpected MTU probe {small.hex()}")
        await self._write("AUTH", bytes.fromhex("00000500") + small[4:])
        big = await self._get("AUTH")
        if big[:4] != bytes.fromhex("00000401"):
            raise ProtocolError(f"unexpected MTU probe {big.hex()}")
        await self._write("AUTH", bytes.fromhex("00000501") + big[4:])
        self.max_value = len(big)

        await asyncio.sleep(0.2)
        await self.client.start_notify(self.chars["LOGIN"], self._notify_handler("LOGIN"))
        await asyncio.sleep(0.05)

    async def login(self):
        rand_key = os.urandom(16)
        await self._write("LOGIN", CMD_LOGIN)
        await self.send_value("AUTH", TAG_RAND_KEY, rand_key)

        tag, remote_key = await self.recv_value("AUTH")
        if tag != TAG_REMOTE_KEY or len(remote_key) != 16:
            raise ProtocolError(f"expected remote_key, got tag {tag:#x} {remote_key.hex()}")
        tag, remote_info = await self.recv_value("AUTH")
        if tag != TAG_REMOTE_INFO or len(remote_info) != 32:
            raise ProtocolError(f"expected remote_info, got tag {tag:#x} {remote_info.hex()}")

        self.keys = derive_session_keys(XIAOMI_TOKEN, rand_key, remote_key)
        expected = hmac.new(self.keys["dev_key"], remote_key + rand_key, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, remote_info):
            raise ProtocolError(
                "remote_info HMAC mismatch -- XIAOMI_TOKEN is wrong (it must be the "
                "cloud 'TOKEN' field, not the BLE KEY/bindkey)"
            )
        login_info = hmac.new(self.keys["app_key"], rand_key + remote_key, hashlib.sha256).digest()
        await self.send_value("AUTH", TAG_LOGIN_INFO, login_info)

        confirm = await self._get("LOGIN")
        if confirm != LOGIN_OK:
            raise ProtocolError(f"login rejected: {confirm.hex()}")

    async def pump(self):
        """Receive and dispatch every PROP value until disconnected."""
        while True:
            try:
                first = await self._get("PROP", forever=True)
                _, data = await self.recv_value("PROP", first)
            except Disconnected:
                return
            except ProtocolError as err:
                log.warning("dropping PROP value: %s", err)
                continue
            except (BleakError, OSError) as err:
                log.warning("PROP receive failed, stopping: %s", err)
                return
            if len(data) < 6:
                log.warning("PROP value too short: %s", data.hex())
                continue
            ctr = struct.unpack("<H", data[:2])[0]
            try:
                pt = aes_ccm_decrypt(self.keys["dev_key"], self.keys["dev_iv"], ctr, data[2:])
                msg = decode_message(pt)
            except (InvalidTag, ProtocolError, IndexError, struct.error) as err:
                log.warning("undecodable PROP value ctr=%d %s: %r", ctr, data.hex(), err)
                continue
            log.info("<- %s", msg)
            if msg.op in (OP_RESULT, OP_HELLO):
                fut = self.pending.get(msg.tid)
                if fut is not None and not fut.done():
                    fut.set_result(msg)
            elif msg.op == OP_EVENT and (msg.siid, msg.iid) == (6, 1):
                self.stored_events.put_nowait(msg)
            elif msg.op == OP_EVENT and msg.siid == 5:
                self.live_events.put_nowait(msg)

    async def request(self, op: int, body: bytes = b"") -> Message:
        self.tid += 1
        tid = self.tid
        pt = encode_message(tid, op, body)
        ct = aes_ccm_encrypt(self.keys["app_key"], self.keys["app_iv"], self.out_ctr, pt)
        payload = struct.pack("<H", self.out_ctr) + ct
        self.out_ctr += 1

        fut = asyncio.get_running_loop().create_future()
        self.pending[tid] = fut
        try:
            await self.send_value("CMD", TAG_DATA, payload)
            return await asyncio.wait_for(fut, RESULT_TIMEOUT_S)
        except asyncio.TimeoutError:
            raise ProtocolError(f"no result for tid {tid} within {RESULT_TIMEOUT_S}s") from None
        finally:
            self.pending.pop(tid, None)
            if fut.done() and not fut.cancelled():
                fut.exception()  # mark a disconnect set by on_disconnect() as seen

    async def action(self, siid: int, aiid: int, *params: bytes) -> Message:
        log.info("-> action %d.%d", siid, aiid)
        result = await self.request(OP_ACTION, bytes([siid, aiid, len(params)]) + b"".join(params))
        if result.status != 0:
            raise ProtocolError(f"action {siid}.{aiid} failed with status {result.status:#x}")
        return result


# --- Sync logic ---------------------------------------------------------------


class Reader:
    """State that outlives a single connection."""

    def __init__(self, http: httpx.AsyncClient):
        self.http = http
        self.last_weight_kg = PROFILE_WEIGHT_KG
        self.last_weight_ts = 0
        self.stored_timestamps: list[int] = []  # of every stored weigh-in the scale sent

    def note_weight(self, w: WeighIn):
        if w.timestamp >= self.last_weight_ts:
            self.last_weight_kg, self.last_weight_ts = w.weight_kg, w.timestamp

    def profile_json(self) -> str:
        return json.dumps(
            {
                "mid": str(PROFILE_MEMBER_ID),
                "duid": 1,
                "uc": 1,
                "ow": 1,
                "unit": 1,
                "time": int(time.time()),
                "ud": [
                    {
                        "duid": 1,
                        "ut": 1,
                        "age": PROFILE_AGE,
                        "sex": PROFILE_SEX,
                        "hi": PROFILE_HEIGHT_CM,
                        "wt": round(self.last_weight_kg * 100),
                    }
                ],
            },
            separators=(",", ":"),
        )

    async def deliver(self, w: WeighIn) -> bool:
        """Deliver one weigh-in. True once it has been (it may then be
        deleted from the scale), False if it should stay there for later."""
        ts = w.timestamp
        if not MIN_PLAUSIBLE_TS <= ts <= time.time() + 300:
            log.warning("weigh-in of %.2f kg has timestamp %d (scale clock not set?), using now", w.weight_kg, ts)
            ts = time.time()
        recorded_at = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        record = {"weight_kg": w.weight_kg, "recorded_at": recorded_at}
        if not WEBHOOK_URL:
            print(json.dumps(record), flush=True)
            return True
        headers = {"Authorization": f"Bearer {WEBHOOK_TOKEN}"} if WEBHOOK_TOKEN else {}
        try:
            resp = await self.http.post(WEBHOOK_URL, headers=headers, json=record)
            resp.raise_for_status()
        except httpx.HTTPError as err:
            log.error("failed to deliver %.2f kg @ %s: %s", w.weight_kg, recorded_at, err)
            return False
        log.info("delivered %.2f kg @ %s", w.weight_kg, recorded_at)
        return True


async def sync_stored(link: ScaleLink, reader: Reader) -> int:
    """Collect, deliver and delete the scale's stored weigh-ins. Returns how
    many the scale sent."""
    result = await link.action(6, 1)
    count = result.params.get(3, 0)
    if not count:
        return 0

    records: list[WeighIn] = []
    deadline = asyncio.get_running_loop().time() + RECORDS_TIMEOUT_S
    while len(records) < count:
        remaining = deadline - asyncio.get_running_loop().time()
        try:
            event = await asyncio.wait_for(link.stored_events.get(), max(remaining, 0))
        except asyncio.TimeoutError:
            log.warning("scale reported %d stored weigh-ins but only sent %d", count, len(records))
            break
        if event is None:
            raise Disconnected("scale disconnected")
        records += parse_stored_records(event.params.get(1, ""))
    log.info("scale sent %d stored weigh-in(s)", len(records))
    reader.stored_timestamps += [r.timestamp for r in records]

    handled = []
    for record in records:
        if not 1 <= record.weight_kg <= 300:
            log.warning("discarding implausible stored weigh-in %s", record)
            handled.append(record.record_no)
            continue
        if await reader.deliver(record):
            handled.append(record.record_no)
            reader.note_weight(record)
    if KEEP_ON_SCALE:
        return len(records)
    for i in range(0, len(handled), 20):
        batch = handled[i : i + 20]
        await link.action(6, 2, param(2, T_STR, ",".join(map(str, batch))))
    if handled:
        log.info("deleted %d stored weigh-in(s) from the scale", len(handled))
    return len(records)


async def listen_live(link: ScaleLink, reader: Reader) -> int:
    """Collect weigh-ins as they happen, until the scale has been quiet for
    LIVE_IDLE_S (LIVE_START_S if nobody was on it at all) or closes the
    connection. Returns how many finished."""
    loop = asyncio.get_running_loop()
    hard_deadline = loop.time() + LIVE_MAX_S
    idle_deadline = loop.time() + LIVE_START_S
    finished = 0
    while (timeout := min(hard_deadline, idle_deadline) - loop.time()) > 0:
        try:
            event = await asyncio.wait_for(link.live_events.get(), timeout)
        except asyncio.TimeoutError:
            break
        if event is None:
            break  # disconnected
        idle_deadline = loop.time() + LIVE_IDLE_S

        if event.iid == 3:
            weight = event.params.get(3, 0) / 100
            log.info("live: %.2f kg%s", weight, " (stable)" if event.params.get(2) else "")
        elif event.iid == 4:
            w = parse_weigh_in(event.params.get(4, ""), numbered=False)
            if w is None:
                log.warning("unparseable finished weigh-in %s", event)
                continue
            finished += 1
            if not await reader.deliver(w):
                continue
            reader.note_weight(w)
            if KEEP_ON_SCALE:
                continue
            # Same as the Xiaomi app. A weigh-in that isn't claimed (or
            # fails to deliver) stays in the scale's memory and is picked
            # up by the next sync_stored() instead.
            try:
                await link.action(
                    4, 3,
                    param(1, T_U64, PROFILE_MEMBER_ID),
                    param(2, T_U8, 1),
                    param(8, T_U16, round(w.weight_kg * 100)),
                )
            except ProtocolError as err:
                log.warning("could not claim the weigh-in (%s); a later sync will collect it again", err)
            except (Disconnected, BleakError):
                break
    return finished


async def run_session(device, reader: Reader) -> int:
    """One connection. Returns how many weigh-ins the scale handed over."""
    link = ScaleLink()
    async with BleakClient(device, disconnected_callback=link.on_disconnect, timeout=20) as client:
        link.client = client
        await link.setup()
        await link.login()
        pump = asyncio.create_task(link.pump())
        try:
            await link.request(OP_HELLO)
            profile = await link.action(7, 1, param(1, T_STR, reader.profile_json()))
            log.info("logged in (firmware %s, %s stored weigh-in(s))", profile.params.get(5), profile.params.get(2))
            collected = await sync_stored(link, reader)
            collected += await listen_live(link, reader)
            if not link.connected:
                log.info("scale closed the connection")
                return collected
            # Anything the scale stored instead of sending live, e.g. a
            # weigh-in that finished while we were still logging in.
            try:
                collected += await sync_stored(link, reader)
            except Disconnected:
                log.info("scale closed the connection")
            return collected
        finally:
            pump.cancel()
            await asyncio.gather(pump, return_exceptions=True)


async def find_scale(timeout: float):
    seen = {}

    def match(device, adv):
        if device.address.upper() != XIAOMI_MAC:
            return False
        seen["adv"] = adv
        return True

    device = await BleakScanner.find_device_by_filter(match, timeout=timeout)
    return device, seen.get("adv")


def beacon_counter(adv) -> int | None:
    """The MiBeacon frame counter from an advertisement, if there is one."""
    beacon = adv.service_data.get(MIBEACON_UUID, b"") if adv is not None else b""
    return beacon[4] if len(beacon) > 4 else None


def beacon_frame_control(adv) -> int | None:
    """The MiBeacon frame control (first two bytes of the 0xfe95 service
    data, little-endian); its flag bits change with the scale's state."""
    beacon = adv.service_data.get(MIBEACON_UUID, b"") if adv is not None else b""
    return int.from_bytes(beacon[:2], "little") if len(beacon) >= 2 else None


def describe_adv(adv) -> str:
    if adv is None:
        return "no advertisement data"
    fc, counter = beacon_frame_control(adv), beacon_counter(adv)
    return (
        f"RSSI {adv.rssi}, MiBeacon frame control {'?' if fc is None else f'{fc:#06x}'}, "
        f"frame counter {'?' if counter is None else f'{counter:#04x}'}"
    )


async def sync_wakeup(device, reader: Reader) -> int | None:
    """run_session() with retries. Returns how many weigh-ins the scale
    handed over, or None if no attempt succeeded."""
    for attempt in range(1, SYNC_ATTEMPTS + 1):
        try:
            return await run_session(device, reader)
        except (BleakError, Disconnected, ProtocolError, asyncio.TimeoutError, OSError) as err:
            log.warning("sync attempt %d/%d failed: %s", attempt, SYNC_ATTEMPTS, str(err) or type(err).__name__)
        except Exception:
            log.exception("sync attempt %d/%d failed unexpectedly", attempt, SYNC_ATTEMPTS)
        if attempt < SYNC_ATTEMPTS:
            await asyncio.sleep(1)
            device, _ = await find_scale(5)
            if device is None:
                log.info("scale went back to sleep; its stored weigh-ins will be collected on the next wake-up")
                return None
    return None


async def main():
    if not XIAOMI_MAC:
        raise SystemExit("XIAOMI_MAC must be set (the scale's Bluetooth address)")
    if len(XIAOMI_TOKEN) != 12:
        raise SystemExit(
            "XIAOMI_TOKEN must be 24 hex chars (the cloud 'TOKEN' field, not the 32-char BLE KEY/bindkey)"
        )

    log.info(
        "watching for %s; delivering to %s%s",
        XIAOMI_MAC, WEBHOOK_URL or "stdout", " (keeping weigh-ins on the scale)" if KEEP_ON_SCALE else "",
    )
    async with httpx.AsyncClient(timeout=10) as http:
        reader = Reader(http)
        expected = None  # MiBeacon frame counter as of the last sync; None until there was one
        last_sync = time.monotonic()
        retry_at = 0.0  # after a failed sync: no new attempt before this
        backoff = FAILED_SYNC_BACKOFF_S
        fruitless: list[float] = []  # when counter-triggered syncs found nothing
        ignore_counter_until = 0.0
        last_seen = None
        advertising = False  # for the log only
        last_beacon = None  # (frame control, counter) last seen, for the log only
        scan_failures = 0
        while True:
            try:
                device, adv = await find_scale(SCAN_WINDOW_S)
                scan_failures = 0
            except (BleakError, OSError) as err:
                scan_failures += 1
                log.warning("scan failed (%d in a row): %s", scan_failures, err)
                if scan_failures >= MAX_SCAN_FAILURES:
                    # Most likely the adapter itself is gone. Exit so a
                    # supervisor restarts this (in the Docker image, the
                    # entrypoint then reloads kernel modules if needed and
                    # waits for hci0 again).
                    raise SystemExit("scanning keeps failing, restarting")
                await asyncio.sleep(SCAN_RETRY_S)
                continue

            now = time.monotonic()
            if device is None:
                if advertising and now - last_seen >= PRESENCE_GAP_S:
                    log.info("scale not seen for %ds (asleep or out of range)", PRESENCE_GAP_S)
                    advertising = False
                continue
            beacon = (beacon_frame_control(adv), beacon_counter(adv))
            if not advertising:
                log.info("scale advertising (%s)", describe_adv(adv))
                advertising = True
            elif beacon != last_beacon:
                log.info("advertisement changed (%s)", describe_adv(adv))
            last_beacon = beacon
            last_seen = now

            counter = beacon_counter(adv)
            by_counter = False
            if now < retry_at:
                reason = None
            elif expected is None:
                reason = f"first sighting since the reader started ({describe_adv(adv)})"
            elif counter is not None and counter != expected and now >= ignore_counter_until:
                reason = f"MiBeacon frame counter is {counter:#04x} instead of {expected:#04x}"
                by_counter = True
            elif now - last_sync >= RESYNC_AFTER_S:
                reason = f"no sync in {RESYNC_AFTER_S // 3600}h"
            else:
                reason = None

            if reason is None:
                await asyncio.sleep(AWAKE_RECHECK_S)
                continue

            log.info("%s, syncing", reason)
            trigger_time = time.time()
            reader.stored_timestamps.clear()
            collected = await sync_wakeup(device, reader)
            now = time.monotonic()
            if collected is None:
                log.info("sync failed; next attempt in %ds at the earliest", backoff)
                retry_at = now + backoff
                backoff = min(backoff * 2, FAILED_SYNC_BACKOFF_MAX_S)
                continue
            backoff = FAILED_SYNC_BACKOFF_S
            last_sync = now

            if by_counter and collected == 0:
                fruitless = [t for t in fruitless if now - t < FRUITLESS_WINDOW_S] + [now]
                if len(fruitless) >= MAX_FRUITLESS_SYNCS:
                    log.warning(
                        "%d counter changes in a row brought nothing new; ignoring the counter for %ds",
                        len(fruitless), FRUITLESS_WINDOW_S,
                    )
                    ignore_counter_until = now + FRUITLESS_WINDOW_S
                    fruitless = []
            # The advertisement that triggered this sync already counted the
            # weigh-ins stored before it; ones stored while we were
            # connecting were collected too, and moved the counter on.
            if counter is not None:
                later = sum(1 for ts in reader.stored_timestamps if ts > trigger_time)
                expected = (counter + later) % 256
                log.info("synced; next sync when the MiBeacon frame counter moves on from %#04x", expected)


if __name__ == "__main__":
    asyncio.run(main())
