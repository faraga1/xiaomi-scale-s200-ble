# Xiaomi Smart Scale S200 (MJTZC02YM) — BLE GATT protocol, reverse-engineered

A from-scratch, byte-verified reverse engineering of how the **Xiaomi Smart
Scale S200** (BLE model, product id/device id prefixed `blt.`) actually
delivers a weight reading over Bluetooth — and a small standalone Python
script (`scale_reader.py`) that logs in and streams readings without the
Xiaomi Home app.

There is no public documentation for this device's protocol. This exists
because the community tooling that *does* support similarly-named Xiaomi
scales (Home Assistant's `xiaomi-ble`, openScale) only implements the
simpler MiBeacon **advertisement**-encryption scheme — and this specific
scale/firmware **never uses it for weight**. Getting a real reading out of
it requires an authenticated GATT session instead. This repo documents
that session end to end.

## The core finding: this scale does not broadcast weight

Every community Xiaomi-scale integration assumes the device pushes its
reading inside an encrypted MiBeacon BLE *advertisement* (a broadcast,
no connection required) — this is how most modern Xiaomi/Mijia sensors
work, and it's what `xiaomi-ble`'s `obj4e16` parser (object id `0x4E16`)
is built to decode.

**Confirmed via extensive live testing** (including a full patient capture
spanning a complete weigh-in cycle, on-scale, watching it wake, measure,
and go back to sleep): this device's advertisements are, in every
observed state, an 11-byte minimal MiBeacon frame — `frame_control` +
`product_id` + `counter` + `MAC` — with **no object payload at all**.
Object `0x4E16` never appears. If your goal is passive/broadcast-only
listening for this exact model, stop here — it won't work; the vendor
never puts weight on the air.

## Where the weight actually is: an authenticated GATT session

The real reading is delivered only after connecting and completing
Xiaomi's older `mible`/"miauth" secure-login scheme — the same general
scheme documented for a couple of other Xiaomi BLE products (e.g. a
diffuser, and a kettle at
[opravdin/hass-yunmi-kettle-ble](https://github.com/opravdin/hass-yunmi-kettle-ble)'s
`PROTOCOL.md`, which was a useful cross-reference for the framing/ack
mechanics below) — followed by a small set of app→device setup commands,
after which the device streams AES-CCM encrypted property pushes,
including the weight record.

### Two different secrets, from the same tool

Both come from running
[`Xiaomi-cloud-tokens-extractor`](https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor)
against your own Xiaomi account, but reading **two different output
fields** — mixing them up is the single most likely reason this will fail
for you:

- **`BLE KEY`** (16 bytes / 32 hex chars) — the MiBeacon *advertisement*
  encryption key. **Not used here** (see above — this device doesn't
  broadcast weight), kept only for completeness / in case a future
  firmware or a sibling model does put something on the air.
- **`TOKEN`** (12 bytes / 24 hex chars — shorter than the usual 16-byte
  Xiaomi miIO token because this is a BLE-only device) — this is the
  actual GATT-login secret, used as the HKDF input key material. This is
  the one `scale_reader.py` needs (`XIAOMI_TOKEN`).

Confirmed correct two independent ways: the derived session key's HMAC
proof matched the real device's own proof byte-for-byte across two
separate capture sessions, and the resulting decryption produced a weight
record that matched the scale's own on-screen reading (89.75 kg) exactly.

### GATT characteristics (service `0xfe95`)

Raw ATT *value handles* are **not stable** for this device — a different
central connecting (this script, vs. the phone in the original captures)
gets handed a completely different handle layout for the identical
characteristics. Resolve these four by **UUID** instead:

| Role  | UUID                                   | Purpose                                                        |
|-------|-----------------------------------------|------------------------------------------------------------------|
| LOGIN | `00000010-0000-1000-8000-00805f9b34fb` | write `CMD_LOGIN`; notifies `CFM_LOGIN_OK`                       |
| AUTH  | `00000019-0000-1000-8000-00805f9b34fb` | miauth key exchange (`rand_key`/`remote_key`/`remote_info`/`login_info`) |
| CMD   | `0000001a-0000-1000-8000-00805f9b34fb` | app → device encrypted commands + flow-control acks              |
| PROP  | `0000001b-0000-1000-8000-00805f9b34fb` | device → app encrypted property/data pushes                      |

### The login handshake (miauth)

1. Write `CMD_LOGIN = 24000000` to LOGIN.
2. On AUTH: send a 16-byte random `rand_key`.
3. Receive the scale's 16-byte `remote_key` (tag `0x0d`) and its 32-byte
   HMAC proof `remote_info` (tag `0x0c`).
4. Derive session keys:
   ```
   HKDF-SHA256(ikm=XIAOMI_TOKEN, salt=rand_key+remote_key,
               info=b"mible-login-info", length=64)
     -> dev_key(16) | app_key(16) | dev_iv(4) | app_iv(4)
   ```
5. Verify the device's proof **before** sending your own (fail fast on a
   wrong token instead of waiting for the device to reject you):
   `HMAC-SHA256(dev_key, remote_key + rand_key) == remote_info`.
6. Send your own proof: `login_info = HMAC-SHA256(app_key, rand_key + remote_key)`.
7. Wait for `CFM_LOGIN_OK = 21000000` on LOGIN.

AES-CCM nonce construction (both directions): `iv(4 bytes) + 00000000 +
counter(4 bytes, little-endian)`, `tag_length=4`.

### The "direct" vs "framed" dual transfer form

Both original phone captures show every AUTH/PROP message delivered as a
single **"direct"** notification: `00 00 02 <tag>` + data, comfortably
fitting inside the official app's negotiated 251-byte ATT_MTU.

A client that does **not** negotiate a larger ATT_MTU (this script
included — see "the MTU trap" below) instead gets the same values
delivered in a **"framed"** (multi-parcel) form, symmetric to the
mechanism the app itself uses for its own outgoing writes:

```
00 00 00 <tag> <parcel_count:le16>      -- header notification
  (repeat parcel_count times:)
  -> write RCV_RDY (00000101)            -- "I'm ready"
  <- <parcel_no:le16><chunk>              -- one parcel, notified
  -> write RCV_OK  (00000100)            -- "got it"
-- concatenate all chunks in order -> the same bytes the direct form
   would have delivered in one shot
```

This isn't specific to AUTH — the **same framed form shows up on PROP
too**, for property pushes, confirmed live even *after* a successful
login. Any client for this device needs to handle both forms on both
characteristics, not just at login.

### The MTU trap

The official app explicitly negotiates ATT_MTU=251 before doing anything
else, which is almost certainly why its captures only ever show the
compact "direct" form. A natural fix is to force a larger MTU yourself —
but depending on your BLE stack, this can be harder than it looks:
`bleak`'s BlueZ backend has a private `BleakClient._acquire_mtu()` method
for exactly this, but **on at least one recent `bleak` version, that
method doesn't exist at all** (`AttributeError`) — silently, unless you
check for it. Rather than depend on MTU negotiation succeeding at all,
this script implements the framed/multi-parcel form properly and treats
a larger MTU as a nice-to-have, not a requirement.

### App→device setup commands

Sent once, in order, right after login (all AES-CCM encrypted with
`app_key`/`app_iv`, framed as single-parcel writes on CMD):

1. **Open session** — op `0xF0`: `[0x05, 0x20, tid_le16, 0xF0]`.
2. **Status probe** — op `0x05`/sub `0x06`:
   `[0x08, 0x20, tid_le16, 0x05, 0x06, 0x01, 0x00]` (purpose not fully
   decoded; both real sessions sent it, harmless to replicate).
3. **User profile push** — op `0x05`/sub `0x07`, a small JSON blob
   (`mid`/`age`/`sex`/`hi` fields) the app sends for the scale's own
   on-device body-composition math. Not required for `weight_kg` itself.
4. **Property subscribe** — op `0x05`/sub `0x06` again, with a
   comma-separated `piid` list appended. **This is the one that matters**:
   empirically, the scale does not push weight-bearing records until
   after this request — it does send small periodic "heartbeat" pushes
   regardless, which conveniently double as liveness checks.

### Decoding a weight record

PROP notifications carry a 2-byte little-endian counter (used as the
AES-CCM nonce counter) followed by the ciphertext+4-byte tag. Decrypt with
`dev_key`/`dev_iv`. A decrypted frame whose 5th byte (`plaintext[4]`) is
`0x07` is a data-record push. Find the `0xa0` marker byte; everything
after it is an ASCII, comma-separated record ending
`...,<flag>,<unix_timestamp>`. **The field immediately before that
trailing pair is the weight, in hundredths of a kilogram** — i.e.
`int(field) / 100 == weight_kg`. Confirmed exact against a real 89.75 kg
on-screen ground-truth reading.

Body composition fields (body fat %, impedance, muscle mass, etc.) are
almost certainly present in some of the other recurring push types that
weren't needed to get weight working and so weren't decoded here — if you
get further on that, a PR or issue with findings is very welcome.

### Known gaps

- **A third PROP notification shape shows up that isn't decoded.**
  Besides the direct and framed forms above, live sessions also produce
  notifications that don't match either prefix, and occasionally a
  direct-form message whose AES-CCM tag simply fails to verify even
  though the same session's login already succeeded (so the key material
  itself is correct). Both look like a third transfer/framing mode this
  writeup hasn't cracked yet — possibly a running per-notification
  sequence number rather than a fixed marker byte, based on the raw bytes
  observed (`03 00...`, `04 00...`, `05 00...` in sequence). `scale_reader.py`
  treats both cases as non-fatal (logs and keeps listening on the same
  connection) rather than tearing down the session over them, since a
  real weight push reliably still arrives afterward in practice. If you
  get further on decoding this shape, that's exactly the kind of finding
  worth a PR or issue.

## How this was actually reverse-engineered

1. On an Android phone with the Xiaomi Home app installed: Developer
   Options → enable "Bluetooth HCI snoop log".
2. Do a real weigh-in with the official app, ideally noting the on-screen
   reading immediately after (ground truth for calibrating the value
   field).
3. Pull the resulting `btsnoop_hci.log` off the phone.
4. Parse the raw btsnoop framing (8-byte file magic + version/datalink
   header, then 24-byte record headers + HCI packet data) and track LE
   Connection Complete events to map connection handles to the scale's BD
   address, then extract every ATT-protocol (GATT) exchange on that
   handle. A small standalone parser for this is included here
   (`parse_btsnoop.py`) since no existing tool does exactly this framing
   extraction.
5. Read the GATT characteristic declarations (`Read By Type Response`,
   ATT opcode `0x09`, GATT UUID `0x2803`) for service `0xfe95` to get the
   stable UUID↔role mapping, independent of the (unstable) raw handles.
6. Diff two independent captures against each other to separate "always
   the same" (protocol/opcodes) from "varies" (session-specific nonces,
   counters, timestamps).
7. Verify the derived crypto material and decoded values against the
   ground-truth on-screen reading before trusting any of it.

If this ever stops working (e.g. after a firmware update), **repeat this
exact process** — capture fresh, diff against what's documented here, and
open an issue/PR with what changed.

## Usage

```bash
pip install -r requirements.txt

export XIAOMI_MAC=AA:BB:CC:DD:EE:FF     # the scale's BLE MAC
export XIAOMI_TOKEN=<24 hex chars>      # the cloud extractor's TOKEN field, NOT the BLE KEY
# optional:
export XIAOMI_BINDKEY=<32 hex chars>    # BLE KEY field; currently unused, kept for parity
export WEBHOOK_URL=https://example.com/ingest   # POSTed {"weight_kg": ...} on every new reading

python scale_reader.py
```

Runs as a persistent daemon: connects, logs in, subscribes, and streams
decrypted readings indefinitely, reconnecting with backoff on disconnect.
Prints every decoded weight to stdout regardless of whether `WEBHOOK_URL`
is set. Backs off much further (`ASLEEP_RETRY_S`, default 60s) when the
scale can't be found via scan at all — this device is asleep almost all
of the time, and constant fast re-scanning was observed live to keep its
display/radio powered on continuously, draining its battery for no
benefit. Only backs off quickly (a few seconds) for failures that happen
once the scale is actually reachable, since a real weigh-in's awake
window is short (observed ~10–30s).

Requires a Bluetooth adapter and a BlueZ stack (`bluetoothd`) the device
running this can talk to over D-Bus — a normal Linux BLE setup. This was
developed and run inside a container with its own internal
`dbus-daemon`/`bluetoothd`, talking to a physical adapter passed through
via `--network host --privileged`; adapt to your own environment.

Only one BLE central can hold a GATT connection to the scale at a time —
if this script is connected when you try to weigh in via the Xiaomi Home
app itself, one of the two logins will fail.

## Origin

Built while getting a personal weight-tracking app to auto-log readings
from this exact scale model, without depending on the Xiaomi Home app.
Extracted here since the protocol itself — not the app it feeds — is what
seemed worth sharing; no other public writeup for this device's GATT
protocol seems to exist.
