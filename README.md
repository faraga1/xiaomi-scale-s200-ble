# Xiaomi Smart Scale S200: Bluetooth protocol and sync client

Everything needed to get weigh-ins off a **Xiaomi Smart Scale S200** over
Bluetooth LE without the Xiaomi Home app or the cloud. It contains:

- a protocol reference, fully decrypted from HCI captures of the official app;
- `scale_reader.py`, a small sync client that delivers every weigh-in, with
  the scale's own timestamp, to a webhook or stdout;
- tools to decrypt your own captures, plus a simulated scale to develop
  against without owning one.

**Status:** verified against one real scale (firmware `2.1.2_0008.0010`),
September–October 2026. The client has collected weigh-ins three ways:
- from the scale's **encrypted broadcasts**, with no connection at all;
- **live**, over a connection;
- from the scale's **memory**, including weigh-ins stored while the
  client was out of range.
There's no official documentation for this protocol; everything here was
reverse-engineered, and the [open questions](#open-questions) list what
isn't known. This README replaces an earlier version that got several key
things wrong. See [corrections](#corrections) if
you used that code.

## Do you need this?

**Every S200 seen so far broadcasts each weigh-in**, as an encrypted
MiBeacon object `0x4e16` (weight, profile id, timestamp) that the
**BLE KEY** decrypts. Home Assistant's
[Xiaomi BLE](https://www.home-assistant.io/integrations/xiaomi_ble/)
integration decodes exactly that, passively, since release 2026.1. If
that works for you, you may not need anything else. This repo adds:
- a standalone client that reads those broadcasts and delivers each
  weigh-in to a webhook;
- the authenticated connection (with the **TOKEN**): it collects
  weigh-ins the broadcasts missed, sets the scale's clock, and clears its
  memory so it can go back to sleep;
- the full protocol, and what goes wrong in practice (a scale that gets
  stuck, below).

The product id is bytes 3–4 of the advertisement's service data for UUID
`0xfe95`, little-endian; e.g. `10 59 cb 4d …` is `0x4dcb`. Any BLE scanner
app shows it.

| Product id | Weigh-in broadcast | Source |
|---|---|---|
| `0x4c04` | Object `0x4e16` | [`xiaomi-ble`](https://github.com/Bluetooth-Devices/xiaomi-ble)'s test data |
| `0x4dcb` | Object `0x4e16`, confirmed 2026-10-07 | This repo's scale (a black/grey `xiaomi.scales.ms113`) |
| `0x45c9` | Unknown | Listed in `xiaomi-ble` |

One `0x4dcb` owner reported that Home Assistant never discovers their
scale ([xiaomi-ble #263](https://github.com/Bluetooth-Devices/xiaomi-ble/issues/263)).
Why isn't known. This repo's own first conclusion, that `0x4dcb` never
broadcasts its weight, was wrong; see [corrections](#corrections).

## The short version

For anyone implementing their own client (Home Assistant, ESPHome, a phone
app...), these are the facts that matter:

1. **Every weigh-in is broadcast, encrypted.** Right after a weigh-in, the
   advertisement carries MiBeacon object `0x4e16`, encrypted with the
   **BLE KEY** (bindkey). A listener gets the weight and timestamp without
   connecting. See [Advertisement](#advertisement).
2. **The scale also keeps every weigh-in in memory** (weight + unix
   timestamp) until a client deletes it. Broadcasts can be missed; the
   memory catches those. Getting at it needs a GATT connection and
   Xiaomi's "miauth" login with the cloud **TOKEN** (12 bytes, a different
   key from the BLE KEY). Fetch with action 6.1, delete with action 6.2.
3. **A connection keeps the scale awake, and a failed one can get it
   stuck.**
   - Never poll-connect: a client that reconnects whenever it sees the
     scale keeps it awake forever, and flattens the batteries.
   - Connect only right after a weigh-in broadcast, when the scale is fully
     awake. Collecting the weigh-in then lets it sleep; left uncollected,
     it kept advertising "connect to me" for 5 minutes.
   - Once, a connection attempt that timed out left the scale stuck
     "connected" for 4.5 days: Bluetooth icon solid, no broadcasts at all,
     and no weigh-ins stored. Only pulling the batteries fixed it.
4. **The frame counter counts broadcast events, not weigh-ins.** That
   includes a status broadcast the scale sends about every 50 minutes.
5. **Values can arrive in pieces.** Anything bigger than one BLE write
   (e.g. a list of stored weigh-ins) arrives as a *framed*, multi-parcel
   transfer. The receiver acknowledges it once before and once after all
   the parcels, not per parcel.
6. **Do the `a4` probe before login.** It tells the scale how big a single
   value can be. Without it, the scale assumes 20 bytes and frames
   everything.

## Quick start

### 1. Get the keys

Run [Xiaomi-cloud-tokens-extractor](https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor)
against the Xiaomi account the scale is paired with. It prints two keys for
the scale, and you want both:
- **`BLE KEY`** (32 hex characters) decrypts the broadcasts;
- **`TOKEN`** (24 hex characters) is the login secret for connecting.

Swapping them is the most common reason things fail. You also need the
scale's Bluetooth MAC address, which the extractor prints too.

### 2. Run it

On a Linux machine with a working BlueZ (`bluetoothd`), run it directly:

```bash
pip install -r requirements.txt
export XIAOMI_MAC=AA:BB:CC:DD:EE:FF
export XIAOMI_TOKEN=0123456789abcdef01234567
export XIAOMI_BINDKEY=0123456789abcdef0123456789abcdef
export WEBHOOK_URL=https://example.com/weigh-ins   # optional, see below
python scale_reader.py
```

On a host without BlueZ (e.g. a Synology NAS), use the Docker image. It runs
its own `dbus-daemon` + `bluetoothd`, so don't use it on a host whose own
`bluetoothd` is using the same adapter:

```bash
docker build -t s200 .
docker run -d --name s200 --restart unless-stopped --net=host --privileged \
  -e XIAOMI_MAC=... -e XIAOMI_TOKEN=... -e XIAOMI_BINDKEY=... -e WEBHOOK_URL=... s200
```

The kernel still needs Bluetooth support. Synology/Xpenology kernels don't
have it; see [xpenology-bt-epyc7002](https://github.com/faraga1/xpenology-bt-epyc7002).
To load out-of-tree modules at startup, mount them at `/bt-modules`
(`-v /path/to/modules:/bt-modules:ro`). The entrypoint then loads them
whenever `hci0` is missing.

### Configuration

| Variable | |
|---|---|
| `XIAOMI_MAC` | Required. The scale's Bluetooth address. |
| `XIAOMI_TOKEN` | Required. The cloud `TOKEN` (24 hex chars), for connecting. |
| `XIAOMI_BINDKEY` | Recommended. The `BLE KEY` (32 hex chars). With it, weigh-ins come from the broadcasts and the client only connects right after one. Without it, it falls back to connecting when the frame counter moves. |
| `WEBHOOK_URL` | Where to POST each weigh-in as JSON: `{"weight_kg": 80.25, "recorded_at": "2026-09-30T07:15:42Z"}`. Unset: prints one JSON line per weigh-in to stdout. |
| `WEBHOOK_TOKEN` | Optional. Sent as `Authorization: Bearer <token>`. |
| `NOTIFY_URL` | Optional. Where to POST alerts as JSON `{"title", "body"}` (with the `WEBHOOK_TOKEN` bearer), e.g. "scale not heard for 12 hours". Unset: alerts only go to the log. |
| `KEEP_ON_SCALE` | `1` = never delete or claim weigh-ins on the scale, e.g. to keep the Xiaomi Home app working alongside. They're then delivered again on every sync, and the scale keeps waking up to offer them. |
| `XIAOMI_PROFILE_MEMBER_ID`, `_AGE`, `_SEX`, `_HEIGHT_CM`, `_WEIGHT_KG` | The user profile pushed to the scale (see [action 7.1](#services)). Only affects the scale's display and user recognition. If you also use the Xiaomi app, set the member id to your account's (the `mid` in the app's own profile push). |
| `LOG_LEVEL` | `DEBUG` logs every raw BLE value. |

A weigh-in only counts as delivered, and gets deleted from the scale, once
the webhook returned 2xx (or it was printed). If your endpoint is down,
weigh-ins stay on the scale until the next sync. The same weigh-in can be
delivered twice (e.g. when a sync is retried), so **deduplicate on
`recorded_at` + `weight_kg`**.

## How the scale behaves

All observed on one unit; see [open questions](#open-questions) for what's
still unclear.

- **Asleep:** no advertising, not connectable. Stepping on it wakes it up.
- **Awake:** advertises every ~0.5 s. With no client connected it goes back
  to sleep ~15 s after the last activity. **While a client is connected it
  stays awake**, and it falls asleep within seconds of the disconnect.
- **Memory:** every finished weigh-in is stored with a record number (which
  keeps counting up, even across battery changes) and a unix timestamp.
  Stored weigh-ins survived 10 days without batteries.
- **Status broadcast:** about every 50 minutes, day and night, the scale
  briefly broadcasts an encrypted object `0x6623` (1 byte, 0 so far; its
  meaning is unknown).
- **After a weigh-in:** it broadcasts the weigh-in (object `0x4e16`). If
  no client collects it, it then advertises "connect to me" (frame control
  `0x5b10`) for about 5 minutes before sleeping. When collected, it sleeps
  within seconds.
- **MiBeacon frame counter** (in the advertisement): goes up with every
  broadcast event, the 50-minute status broadcasts included. It restarts
  at 0 when the batteries go in. (Earlier it looked like it counted stored
  weigh-ins: it went up in step with them, and the status broadcasts
  explained the rest.)
- **Stuck "connected":** after a connection attempt that timed out, the
  scale once behaved as if still connected for 4.5 days. When stepped on,
  its Bluetooth icon was solid instead of blinking; it sent no broadcasts at
  all (not even the 50-minute ones); and it didn't store the weigh-ins made
  in the meantime. Pulling the batteries for 10 s fixed it. So keep
  connection attempts rare. If the scale stays silent for many hours,
  suspect this (`scale_reader.py` alerts after 12 h).
- **Clock:** set by the `"time"` field of the profile push (action 7.1).
  Record timestamps are UTC unix time.
- **User recognition:** a stored weigh-in has flag `0` plus the member id if
  its weight was close to the profile's reference weight (`"wt"`).
  Otherwise it has flag `2` and member id `0`. The weight is stored either
  way.
- **One client at a time.** The Xiaomi Home app deletes the stored weigh-ins
  it collects, so anything it syncs never reaches your client.

## Protocol reference

### Advertisement

Service data for UUID `0xfe95` (MiBeacon v5):
`<frame control:le16> <product id:le16> <frame counter:u8> [MAC, reversed] [payload]`.
The frame control says what follows:

| Frame control | Contents | When (this repo's `0x4dcb` scale) |
|---|---|---|
| `0x5910` | MAC, no object | Awake, e.g. after a connection |
| `0x5b10` | MAC, no object; bit 9 set | Awake, wants a client ("connect to me"), e.g. while a weigh-in waits to be collected |
| `0x5958` | MAC + encrypted object | Status object `0x6623`, every ~50 minutes |
| `0x5948` | Encrypted object, no MAC | Weigh-in object `0x4e16`, right after a weigh-in |

Bit `0x08` = encrypted, `0x10` = MAC included, `0x40` = object included.
Another S200 client
([esp32-mirror-weight-tracker](https://github.com/kfirmaymon84/esp32-mirror-weight-tracker))
saw `0x5830` when idle and `0x5b10` when someone steps on.

**Decrypting an object frame** (AES-CCM, 4-byte tag, key = BLE KEY):
- the payload after the MAC (if any) is `<ciphertext> <extended counter:3> <tag:4>`;
- nonce = MAC (little-endian, from the frame, or the scale's own if not
  included) + product id (2) + frame counter (1) + extended counter (3);
- associated data: the single byte `0x11`;
- the plaintext is one or more objects `<id:le16> <length:u8> <value>`.

| Object | Value |
|---|---|
| `0x4e16` | 9 bytes: `<profile id:u8> <weight:le32, 1/100 kg> <unix time:le32>`, e.g. `01 2f1c0000 803bb16a` = profile 1, 72.15 kg, 2026-09-21 14:13:20 UTC |
| `0x6623` | 1 byte, `00` so far; meaning unknown |

The timestamp comes from the scale's clock, which is only set by a
connection (the profile push, action 7.1). The scan response carries the
name `Xiaomi Scale S200 XXXX` (the last four hex digits of the MAC).

### GATT

All four characteristics are in service `0xfe95`. **Look them up by UUID.**
ATT handles differ between clients (the phone and a Linux/BlueZ client got
different layouts).

| Name | UUID | Direction |
|---|---|---|
| LOGIN | `00000010-0000-1000-8000-00805f9b34fb` | write `a4` / `24000000`; notifies `21000000` on login |
| AUTH | `00000019-0000-1000-8000-00805f9b34fb` | payload-size probe and key exchange, both ways |
| CMD | `0000001a-0000-1000-8000-00805f9b34fb` | encrypted requests, app → scale (+ acks back) |
| PROP | `0000001b-0000-1000-8000-00805f9b34fb` | encrypted results and events, scale → app (+ acks back) |

Enable notifications on AUTH, CMD and PROP, then do the probe, and only then
enable LOGIN. That's the Xiaomi app's order, with ~200 ms before the login
starts. A client that enabled all four up front and started the login
straight after the probe got no answer to about half its logins. After
switching to the app's order, every login attempt observed so far (4 of
4) succeeded first time. The root cause isn't known.

### Framing (AUTH, CMD, PROP)

Every value is sent one of two ways:

- **Direct**: `00 00 02 <tag> <data>`, when the value fits in one write. The
  receiver answers `00 00 03 00`.
- **Framed**: when it doesn't fit.

  ```
  sender   → 00 00 00 <tag> <n:le16>      header: n parcels follow
  receiver → 00 00 01 01                  ready (once)
  sender   → 01 00 <chunk>                parcel 1
  sender   → 02 00 <chunk>                parcel 2   (back to back, no ack in between)
  ...
  sender   → <n:le16> <chunk>             parcel n
  receiver → 00 00 01 00                  received (once)
  ```

  The value is the chunks concatenated in parcel order. A full parcel
  carries *(max value size − 2)* bytes.

Tags: `0x00` encrypted data (CMD/PROP), `0x0b` rand_key, `0x0d` remote_key,
`0x0c` remote_info, `0x0a` login_info. The scale uses direct whenever it
can. The Xiaomi app (and this client) always sends framed, even for a
single parcel.

**Payload-size probe (before login):** write `a4` to LOGIN. On AUTH the
scale sends `00 00 04 00 06 f2`, which you echo as `00 00 05 00 06 f2`. It
then sends `00 00 04 01` + a run of `f2` bytes, which you echo back the same
way (`04 01` → `05 01`). The length of that big probe is the largest value
the scale accepts in one write: 244 bytes at the 251-byte ATT MTU that BlueZ
and Android negotiate. Skip the probe and the scale assumes 20 bytes.

### Login (miauth)

```
LOGIN ← 24 00 00 00
AUTH  ⇄ rand_key (tag 0x0b, 16 random bytes)                    app → scale
AUTH  ⇄ remote_key (tag 0x0d, 16 bytes)                          scale → app
AUTH  ⇄ remote_info (tag 0x0c, 32 bytes)                         scale → app
        keys = HKDF-SHA256(ikm=TOKEN, salt=rand_key + remote_key,
                           info=b"mible-login-info", length=64)
        dev_key, app_key, dev_iv, app_iv = keys[0:16], keys[16:32], keys[32:36], keys[36:40]
        check remote_info == HMAC-SHA256(dev_key, remote_key + rand_key)   # wrong token fails here
AUTH  ⇄ login_info = HMAC-SHA256(app_key, rand_key + remote_key) (tag 0x0a)   app → scale
LOGIN → 21 00 00 00                                             login OK
```

### Encryption

After login, every CMD/PROP value is `<ctr:le16><AES-CCM ciphertext, 4-byte
tag>`:

- nonce = `iv (4 bytes) + 00 00 00 00 + ctr (le32)`, no associated data;
- `app_key`/`app_iv` for app → scale, with your own counter starting at 0;
- `dev_key`/`dev_iv` for scale → app, using the counter in each value.

### Messages

Decrypted payloads are Xiaomi MIoT-spec operations:

```
<len_type:le16 = 0x2000 | total_length> <tid:le16> <op> <body>

op 0xf0  hello     no body; the scale echoes it (same tid). Sent first.
op 0x05  action    <siid> <aiid> <n> <n params>
op 0x06  result    <status:le16> [<n> <n params>]     reply to an action, same tid
op 0x07  event     <siid> <eiid> 00 <n> <n params>    sent by the scale (own tids)

param:   <piid:le16> <type_len:le16 = type << 12 | length> <value>
types seen: 0x1 u8, 0x3 u16 (le), 0x8 u64 (le), 0xa string
```

Example: a live-weight event, 90.00 kg, not yet stable:

```
19 20  0f 00  07  05 03 00 03   01 00 01 10 00   02 00 01 10 00   03 00 02 30 28 23
len    tid    ev  5.3   (3 params) p1 u8 = 0      p2 u8 = 0         p3 u16 = 0x2328 = 9000
```

### Services

| | Params | Meaning |
|---|---|---|
| action **7.1** | p1 = profile JSON (string) | Set the user profile and the clock. Result: p2 = number of stored weigh-ins, p3 = serial, p4 = MAC, p5 = firmware, p6 = 0. The Xiaomi app sends this right after hello on every connection. |
| action **6.1** | none | Fetch stored weigh-ins. Result: p3 = count. If non-zero, the scale then sends **event 6.1**, p1 = the records (below), framed when long. |
| action **6.2** | p2 = `"41,42,43"` | Delete stored weigh-ins by record number. The app deletes everything it fetched. |
| event **5.3** | p1 = 0, p2 = stable (0/1), p3 = weight (u16, 1/100 kg) | Live weight while someone is on the scale, ~every 0.7 s. |
| event **5.4** | p4 = `"member_id,user_type,weight,flag,ts"` | The weigh-in finished. |
| action **4.3** | p1 = member id (u64), p2 = 1 (u8), p8 = weight (u16) | Claim a finished weigh-in (the app does this after every 5.4). A claimed weigh-in isn't stored. |

Profile JSON, exactly as the app sends it (keys in this order):

```json
{"mid":"<member id>","duid":1,"uc":1,"ow":1,"unit":1,"time":<unix now>,"ud":[{"duid":1,"ut":1,"age":30,"sex":1,"hi":180,"wt":8025}]}
```

`wt` is the user's current weight in 1/100 kg; the app sends the latest
weigh-in. `unit` 1 = kg.

Stored weigh-ins (event 6.1, p1): records joined by `_`, oldest first,
each `no,member_id,user_type,weight,flag,unix_ts`, e.g.

```
41,1,1,8025,0,1790000000_42,0,0,7260,2,1790000060
```

The weight is in 1/100 kg: `8025` is 80.25 kg. `flag` 0 = recognised user,
2 = unrecognised (member id 0, user_type 0).

**No body-composition values** (impedance, body fat...) appear anywhere in
the protocol. As far as the traffic shows, the S200 only measures weight.

### A sync session

```
connect; notify on AUTH, CMD, PROP; probe; ~200 ms; notify on LOGIN; login
→ hello                         ← hello
→ action 7.1 (profile + clock)  ← result: 12 stored
→ action 6.1                    ← result: count 12
                                ← event 6.1: 12 records (framed, 2 parcels)
  (deliver them)
→ action 6.2 "29,...,40"        ← result: ok
                                ← event 5.3 ×n, then 5.4   (if someone is on the scale)
→ action 4.3 (claim)            ← result: ok
disconnect as soon as it's quiet
```

Live events can arrive at any point after login, even before hello. A
client needs a receive loop that dispatches results (by tid) and events
independently of whatever request it's waiting on.

## Designing a client

`scale_reader.py` does the following (with a BLE KEY):

1. **Only scan, and decrypt every advertisement.** Scanning doesn't keep
   anything awake.
2. **Weigh-in broadcast (`0x4e16`) → deliver it**, with the scale's
   timestamp. One broadcast event (frame counter + extended counter) is
   handled once, however often it's seen.
3. **Right after a weigh-in broadcast, connect once.** At most once per
   10 minutes, and at most 2 attempts. Log in, push the profile (this sets
   the clock), fetch/deliver/delete the stored weigh-ins, listen briefly
   for live weigh-ins, and disconnect. The scale is fully awake then,
   which is when connections work, and collecting the weigh-in lets it
   sleep. A failed attempt waits for the next weigh-in.
4. **Never connect otherwise.** No timers, no catch-up syncs, nothing on
   the 50-minute status broadcasts. Connection attempts during those all
   failed, and one of them most likely left the scale stuck.
5. **Alert when the scale goes silent** for 12 hours (normally there's a
   broadcast every ~50 minutes). Once, until it's heard again.

Without a BLE KEY it can't read the broadcasts, and connects when the frame
counter differs from what it should be after the last sync. That's the
counter in the advertisement that triggered the sync, plus any stored
weigh-ins collected that are newer than it. Since the status broadcasts
also move the counter, it ignores the counter for an hour after 3
fruitless syncs. Failed syncs back off from 1 minute, doubling, up to 30.

What *not* to do:
- **Treat "not seen for a scan window" as asleep, and the next sighting as
  a wake-up worth a connection.** At −80 dBm the scale's advertisements go
  missing for 10 s at a time while it's awake. That rule connected ~20
  times in 20 minutes without a single weigh-in, keeping the scale awake.
- **Retry connections for as long as the scale is visible.** That's how it
  got stuck.

## Tools

| File | |
|---|---|
| `scale_reader.py` | The sync client. Its docstring is a condensed version of this README. |
| `test_scale_reader.py` | Runs the real client code against `FakeScale`, a simulation of the scale's side of the protocol. No Bluetooth needed: `python -m unittest test_scale_reader -v`. Start here if you're porting this to another language or platform. |
| `decode_btsnoop.py` | Decrypts an Android HCI snoop capture: both directions, direct and framed, all messages decoded. `XIAOMI_TOKEN=... python decode_btsnoop.py btsnoop_hci.log <mac>` |
| `parse_btsnoop.py` | Dumps the raw ATT traffic of a capture (no decryption); useful to re-derive handles. |
| `Dockerfile`, `entrypoint.sh` | Self-contained BlueZ for hosts without one. |

## How this was reverse-engineered

1. On an Android phone: Developer options → **Enable Bluetooth HCI snoop
   log**. Then do a weigh-in with the Xiaomi Home app (ideally noting the
   weight on the display), and pull `btsnoop_hci.log` off the phone
   (`adb bugreport`, or it's under `/data/misc/bluetooth/logs`).
2. `parse_btsnoop.py` extracts the ATT traffic for the scale's connection.
   `decode_btsnoop.py` derives the session keys from the token and decrypts
   everything.
3. Decoding the payloads as MIoT operations (actions, results, events with
   typed parameters) is what made the meaning of each exchange clear.
   Replaying captured byte sequences without that structure led the first
   version of this repo astray.

**If a firmware update breaks something**, capture the app again and diff
its decoded conversation against this README. HCI snoop logs contain
everything else the phone's Bluetooth did during the capture (other
devices, notification contents...), so don't publish them.

## Open questions

- **Stalled logins:** why roughly half the logins stalled without the app's
  notification order and pause, or whether that's the real fix.
- **Object `0x6623`:** what the 50-minute status broadcast means.
- **The stuck state:** exactly what triggers it, and whether the scale ever
  recovers from it by itself.
- **Clock after a battery change:** what timestamps the scale gives
  weigh-ins before the first profile push sets its clock.
  `scale_reader.py` replaces implausible ones with the current time.
- **Event 5.3 p1:** always 0 so far.
- **Other units:** `unit` values for lb/jin, and whether weights are then
  still in 1/100 kg.
- **Multiple users:** `uc`/`ud` with more than one user.
- **Memory capacity:** at least 18 weigh-ins were seen stored at once.
- **The other characteristic:** before login, the app also runs a short
  exchange on another characteristic (handle `0x0025` for the phone). It
  returns chip info such as `nrf52840`. Skipping it made no difference.

## Corrections

**October 2026.** The September 30 rewrite of this README said the
`0x4dcb` variant never broadcasts its weight, and that the frame counter
counts stored weigh-ins. Both were wrong:
- it broadcasts every weigh-in as object `0x4e16`, which the phone
  captures behind that conclusion simply didn't contain;
- the counter counts broadcast events, the 50-minute status broadcasts
  included.

**The first version of this repo (September 18)** replayed captured
bytes without understanding them, and got these wrong:

- **Its "status probe" was *fetch stored weigh-ins*** (action 6.1), and **its
  "property subscribe `1,2,…,9`" was *delete stored weigh-ins #1–9***
  (action 6.2). That old script deleted a new scale's first nine weigh-ins
  on every connection.
- **The framed transfer was acknowledged per parcel.** The protocol uses one
  "ready" and one "received" per value. Nor did the old script ever collect
  the stored weigh-ins.
- **"The MTU trap"**: whether the scale sends direct or framed depends on
  the `a4` probe and the size of the value, not on ATT MTU negotiation.
- **The undecoded "third notification shape" (`03 00…`, `04 00…`)** was
  just parcels 3, 4, ... of a framed transfer. The "bad CCM tag" warnings
  were framed headers mistaken for encrypted messages.
- **Body composition** isn't in the protocol at all.
- **Battery advice:** scanning doesn't wake the scale, connecting does. The
  old reconnect loop is what kept it awake.

## Related

- [xpenology-bt-epyc7002](https://github.com/faraga1/xpenology-bt-epyc7002):
  Bluetooth kernel modules for Xpenology, which this ran on.
- [Xiaomi-cloud-tokens-extractor](https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor):
  getting the token.
- [opravdin/hass-yunmi-kettle-ble `PROTOCOL.md`](https://github.com/opravdin/hass-yunmi-kettle-ble):
  the same miauth scheme on a kettle, which was a useful cross-reference for
  the login.
- [kfirmaymon84/esp32-mirror-weight-tracker](https://github.com/kfirmaymon84/esp32-mirror-weight-tracker):
  an ESP32 client for the S200 (live weights only, on a bathroom-mirror
  display). It arrived at the same login independently, and is the source
  of the idle/active frame-control observation.
- [nokistin/xiaomi-s400-live](https://github.com/nokistin/xiaomi-s400-live)
  and [1260er/ScaleLauncher](https://github.com/1260er/ScaleLauncher): the
  same protocol on the S400 body-composition scale, with live weight and
  impedance.
- [dnandha/miauth](https://github.com/dnandha/miauth): the original
  reverse engineering of this login scheme (on Xiaomi scooters).

## License

MIT (see `LICENSE`).
