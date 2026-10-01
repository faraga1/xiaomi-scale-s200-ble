# Xiaomi Smart Scale S200: Bluetooth protocol and sync client

Everything needed to get weigh-ins off a **Xiaomi Smart Scale S200** over
Bluetooth LE without the Xiaomi Home app or the cloud. It contains:

- a protocol reference, fully decrypted from HCI captures of the official app;
- `scale_reader.py`, a small sync client that delivers every weigh-in, with
  the scale's own timestamp, to a webhook or stdout;
- tools to decrypt your own captures, plus a simulated scale to develop
  against without owning one.

**Status:** verified against one real scale (firmware `2.1.2_0008.0010`) in
September 2026: the client collected weigh-ins both live and from the
scale's memory, including ones stored while it was out of range. The
connect policy described under [Designing a client](#designing-a-client)
replaced an earlier one on 2026-10-01, after that one looped at a weak
signal; it hasn't been through a real weigh-in yet.
There's no official documentation for this protocol; everything here was
reverse-engineered, and the [open questions](#open-questions) list what
isn't known. This README replaces an earlier version that got several key
things wrong. See [corrections](#corrections-to-the-first-version) if
you used that code.

## The short version

For anyone implementing their own client (Home Assistant, ESPHome, a phone
app...), these are the facts that matter:

1. **The weight is never broadcast.** Advertisements only carry a minimal
   MiBeacon frame. You have to connect over GATT and log in with Xiaomi's
   "miauth" scheme, using the device's cloud **TOKEN** (12 bytes). That's
   not the "BLE KEY"/bindkey that other Xiaomi sensors use.
2. **The scale keeps every weigh-in in memory** (weight + unix timestamp)
   until a client deletes it. You don't need to be connected while someone
   weighs themselves. Fetch the stored weigh-ins later (action 6.1), then
   delete them (action 6.2).
3. **The advertisements tell you when there's something new.** The MiBeacon
   frame counter goes up by one for every weigh-in the scale stores. So a
   passive listener knows when to connect, without connecting.
4. **A connection keeps the scale awake.** Never poll-connect: a client
   that reconnects whenever it sees the scale keeps it awake forever, and
   flattens the batteries. **Connect only when the counter says there's
   something new**, not when the scale "reappears". At a weak signal,
   advertisements go missing for 10 s at a time while the scale is awake,
   and "reconnect when it reappears" becomes the same keep-awake loop.
   Disconnect as soon as nobody is on the scale.
5. **Values can arrive in pieces.** Anything bigger than one BLE write
   (e.g. a list of stored weigh-ins) arrives as a *framed*, multi-parcel
   transfer. The receiver acknowledges it once before and once after all
   the parcels, not per parcel.
6. **Do the `a4` probe before login.** It tells the scale how big a single
   value can be. Without it, the scale assumes 20 bytes and frames
   everything.

## Quick start

### 1. Get the token

Run [Xiaomi-cloud-tokens-extractor](https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor)
against the Xiaomi account the scale is paired with. It prints two keys for
the scale; you need **`TOKEN`** (24 hex characters). **`BLE KEY`** (32 hex
characters) is the advertisement key and doesn't work for this. Mixing them
up is the most common reason logins fail. You also need the scale's
Bluetooth MAC address, which the extractor prints too.

### 2. Run it

On a Linux machine with a working BlueZ (`bluetoothd`), run it directly:

```bash
pip install -r requirements.txt
export XIAOMI_MAC=AA:BB:CC:DD:EE:FF
export XIAOMI_TOKEN=0123456789abcdef01234567
export WEBHOOK_URL=https://example.com/weigh-ins   # optional, see below
python scale_reader.py
```

On a host without BlueZ (e.g. a Synology NAS), use the Docker image. It runs
its own `dbus-daemon` + `bluetoothd`, so don't use it on a host whose own
`bluetoothd` is using the same adapter:

```bash
docker build -t s200 .
docker run -d --name s200 --restart unless-stopped --net=host --privileged \
  -e XIAOMI_MAC=... -e XIAOMI_TOKEN=... -e WEBHOOK_URL=... s200
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
| `XIAOMI_TOKEN` | Required. The cloud `TOKEN` (24 hex chars). |
| `WEBHOOK_URL` | Where to POST each weigh-in as JSON: `{"weight_kg": 80.25, "recorded_at": "2026-09-30T07:15:42Z"}`. Unset: prints one JSON line per weigh-in to stdout. |
| `WEBHOOK_TOKEN` | Optional. Sent as `Authorization: Bearer <token>`. |
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
- **Self-wake:** once, the scale fell asleep while holding an uncollected
  weigh-in, then advertised again ~3 minutes later with nobody near it. It
  was also seen advertising with an empty memory, with nobody near it and no
  app in use. So it does wake up by itself; when and why isn't understood.
- **MiBeacon frame counter** (in the advertisement): +1 for every weigh-in
  stored in memory (4 of 4 observed: 0 → 6 → 7 → 8, in step with stored
  records). A weigh-in a client claims live (action 4.3) isn't stored, and
  doesn't count. It restarts at 0 when the batteries go in. It was also
  seen going up by 4 within 3 hours without any stored weigh-in, while
  nobody touched the scale and no app was used. So the scale also moves it
  by itself, for reasons unknown.
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

Service data for UUID `0xfe95`: `10 59 cb 4d NN <MAC, reversed>`.

| Bytes | Meaning |
|---|---|
| `10 59` | frame control `0x5910`: MiBeacon v5, bound, MAC included, no object, not encrypted |
| `cb 4d` | product id `0x4dcb` |
| `NN` | frame counter (stored weigh-ins since power-on) |
| MAC | little-endian |

The scan response carries the name `Xiaomi Scale S200 XXXX` (the last four
hex digits of the MAC). No object ever appears: no weight, not even
encrypted. Tooling that decodes MiBeacon objects (e.g. Home Assistant's
`xiaomi-ble`) can't read this scale.

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
41,1,1,8025,0,1790000000_42,0,0,9260,2,1790000060
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

`scale_reader.py` does the following:

1. **Only scan.** Check the frame counter in the scale's advertisements
   every ~2 s while it's advertising. Scanning doesn't keep anything
   awake.
2. **Connect only when the counter differs from what it should be after
   the last sync.** That's the counter in the advertisement that
   triggered the sync, plus any stored weigh-ins collected that are newer
   than that advertisement. A finished weigh-in gets stored, and shows up
   as a new counter value a few seconds later. The only other reasons to
   connect: the first sighting after the client starts, and a daily
   safety sync.
3. **Sync:** log in, push the profile (this sets the clock), then fetch,
   deliver and delete the stored weigh-ins. Retry a failed login up to 4
   times.
4. **Stay connected only while someone is using the scale.** Disconnect 5 s
   after syncing if there's no live weight, or 15 s after the last live
   update. Then check the store once more. If someone steps on again after
   the disconnect, that weigh-in gets stored and moves the counter.
5. **Never let it loop.**
   - A sync that fails outright backs off (1 min, doubling to 30 min); the
     weigh-ins stay on the scale until a sync succeeds.
   - Counter changes that bring nothing new each cost one sync. After 3
     within an hour, ignore the counter for an hour.

What *not* to do: treat "not seen for a scan window" as asleep and the next
sighting as a wake-up worth a connection. That's what this client did
before. At −80 dBm it missed the scale's advertisements for 10 s at a time
while the scale was awake, and connected ~20 times in 20 minutes without a
single weigh-in. The connections kept the scale awake.

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
- **Self-wake:** when and why the scale wakes up by itself (see
  [How the scale behaves](#how-the-scale-behaves)). `scale_reader.py` logs
  when the scale starts and stops advertising, ignoring gaps under 60 s,
  so its logs show the pattern over time.
- **The frame counter's other increments:** what else, besides a stored
  weigh-in, moves it.
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

## Corrections to the first version

The first version of this repo (September 18) replayed captured bytes
without understanding them, and got these wrong:

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

## License

MIT (see `LICENSE`).
