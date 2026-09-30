"""
Offline decoder: replays an Android btsnoop HCI capture of a client (the
Xiaomi Home app, or anything else) talking to the scale through
scale_reader.py's own framing/crypto/message code, and prints the decrypted
conversation -- both directions, direct and framed values alike.

Usage: XIAOMI_TOKEN=<hex> python decode_btsnoop.py <btsnoop_path> <scale_mac>

Reads the token from the environment, not argv, so it never ends up in a
shell history. The Docker image ships this file too, so with the reader
running as a container (named s200 here) that already has XIAOMI_TOKEN:
    docker exec -i s200 sh -c 'cat > /tmp/capture.log' < btsnoop_hci.log
    docker exec s200 python3 decode_btsnoop.py /tmp/capture.log <mac>

HCI snoop captures contain everything else the phone's Bluetooth did during
the capture (other devices, notification contents...). Don't publish them.

The ATT handles below are the ones the Xiaomi app's connections get
(stable across every app capture so far). Another client can get a
different layout -- parse_btsnoop.py dumps the raw GATT discovery needed to
re-derive them.
"""
import hashlib
import hmac
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scale_reader import (  # noqa: E402
    OP_EVENT,
    TAG_LOGIN_INFO,
    TAG_RAND_KEY,
    TAG_REMOTE_INFO,
    TAG_REMOTE_KEY,
    aes_ccm_decrypt,
    decode_message,
    derive_session_keys,
    parse_stored_records,
    parse_weigh_in,
)

HANDLES = {0x0013: "LOGIN", 0x0016: "AUTH", 0x001F: "CMD", 0x0022: "PROP"}
CONTROL = {"00000101": "ready", "00000100": "received", "00000300": "ack"}


def att_records(path, mac):
    """Yield (seconds, kind, direction, handle, value) for one device."""
    target = bytes(reversed(bytes.fromhex(mac.replace(":", ""))))
    conns = set()
    t0 = None
    with open(path, "rb") as f:
        if f.read(8) != b"btsnoop\x00":
            raise SystemExit("not a btsnoop file")
        f.read(8)
        while len(header := f.read(24)) == 24:
            _, incl_len, flags, _, ts = struct.unpack(">IIIIq", header)
            data = f.read(incl_len)
            if not data:
                continue
            t0 = ts if t0 is None else t0
            t = (ts - t0) / 1e6
            if data[0] == 0x04:  # HCI event
                p = data[1:]
                if p[0] == 0x3E and p[2] in (0x01, 0x0A) and p[8:14] == target:
                    conns.add(struct.unpack("<H", p[4:6])[0])
                    yield t, "connect", None, None, None
                elif p[0] == 0x05 and len(p) >= 6 and struct.unpack("<H", p[3:5])[0] in conns:
                    yield t, "disconnect", None, None, p[5:6]
            elif data[0] == 0x02:  # ACL data
                p = data[1:]
                if struct.unpack("<H", p[0:2])[0] & 0x0FFF not in conns or len(p) < 9:
                    continue
                cid = struct.unpack("<H", p[6:8])[0]
                att = p[8:]
                # Write Request, Write Command, Handle Value Notification
                if cid == 0x0004 and att and att[0] in (0x12, 0x52, 0x1B) and len(att) >= 3:
                    direction = "app" if flags & 0x01 == 0 else "scale"
                    yield t, "att", direction, struct.unpack("<H", att[1:3])[0], att[3:]


class Reassembler:
    """One direction of one characteristic's framing layer."""

    def __init__(self):
        self.expect = 0
        self.tag = None
        self.parcels = {}
        self.last_parcel = None

    def feed(self, value):
        if self.expect:
            self.parcels[struct.unpack("<H", value[:2])[0]] = value[2:]
            self.last_parcel = value
            if len(self.parcels) < self.expect:
                return None
            self.expect = 0
            return "framed", self.tag, b"".join(self.parcels[k] for k in sorted(self.parcels))
        if value == self.last_parcel:
            return None  # the Xiaomi app writes every CMD parcel twice
        if len(value) == 6 and value[:3] == b"\x00\x00\x00":
            self.expect, self.tag, self.parcels = struct.unpack("<H", value[4:6])[0], value[3], {}
            return None
        if len(value) >= 4 and value[:3] == b"\x00\x00\x02":
            return "direct", value[3], value[4:]
        return "control", None, value


def describe(msg):
    text = str(msg)
    if msg.op == OP_EVENT and (msg.siid, msg.iid) == (6, 1):
        records = parse_stored_records(msg.params.get(1, ""))
        text += "\n" + "\n".join(f"{'':12}stored #{r.record_no}: {r.weight_kg:.2f} kg @ {r.timestamp}" for r in records)
    elif msg.op == OP_EVENT and (msg.siid, msg.iid) == (5, 4):
        w = parse_weigh_in(msg.params.get(4, ""), numbered=False)
        text += f"\n{'':12}finished weigh-in: {w.weight_kg:.2f} kg @ {w.timestamp}" if w else ""
    return text


def main(path, mac):
    token = bytes.fromhex(os.environ["XIAOMI_TOKEN"])
    chans = keys = rand_key = remote_key = None
    for t, kind, direction, handle, value in att_records(path, mac):
        if kind == "connect":
            print(f"\n{t:9.3f} ===== connected =====")
            chans, keys, rand_key, remote_key = {}, None, None, None
            continue
        if kind == "disconnect":
            print(f"{t:9.3f} ===== disconnected (reason {value.hex()}) =====")
            continue
        name = HANDLES.get(handle)
        if name is None or chans is None:
            continue
        if name == "LOGIN":
            print(f"{t:9.3f} {direction:>5} LOGIN {value.hex()}")
            continue

        result = chans.setdefault((name, direction), Reassembler()).feed(value)
        if result is None:
            continue
        form, tag, data = result
        if form == "control":
            label = CONTROL.get(data.hex(), f"mtu-probe {data[:4].hex()} +{len(data) - 4}B" if name == "AUTH" else data.hex())
            print(f"{t:9.3f} {direction:>5} {name} {label}")
            continue

        if name == "AUTH":
            if tag == TAG_RAND_KEY:
                rand_key = data
            elif tag == TAG_REMOTE_KEY:
                remote_key = data
            elif tag == TAG_REMOTE_INFO and rand_key and remote_key:
                keys = derive_session_keys(token, rand_key, remote_key)
                ok = hmac.new(keys["dev_key"], remote_key + rand_key, hashlib.sha256).digest() == data
                print(f"{t:9.3f} {direction:>5} AUTH remote_info ({form}), token {'OK' if ok else 'WRONG'}")
                continue
            label = {TAG_RAND_KEY: "rand_key", TAG_REMOTE_KEY: "remote_key", TAG_LOGIN_INFO: "login_info"}.get(tag, f"tag {tag:#x}")
            print(f"{t:9.3f} {direction:>5} AUTH {label} ({form})")
            continue

        if keys is None:
            print(f"{t:9.3f} {direction:>5} {name} ({form}, no session keys) {data.hex()}")
            continue
        ctr = struct.unpack("<H", data[:2])[0]
        key, iv = (keys["app_key"], keys["app_iv"]) if direction == "app" else (keys["dev_key"], keys["dev_iv"])
        try:
            pt = aes_ccm_decrypt(key, iv, ctr, data[2:])
        except Exception:
            print(f"{t:9.3f} {direction:>5} {name} ({form}) ctr={ctr} DECRYPT FAILED {data.hex()}")
            continue
        try:
            text = describe(decode_message(pt))
        except Exception as err:
            text = f"undecodable ({err}) {pt.hex()}"
        print(f"{t:9.3f} {direction:>5} {name} ({form}) {text}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
