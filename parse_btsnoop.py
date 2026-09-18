"""
Minimal btsnoop parser focused on finding GATT (ATT protocol) traffic to/from
a specific BLE device, by tracking LE connection-complete events to map
HCI connection handles to BD_ADDR, then decoding ACL data packets on the
ATT fixed channel (L2CAP CID 0x0004).

Used to reverse-engineer this scale's protocol from a real Android HCI
snoop log (Developer Options -> "Enable Bluetooth HCI snoop log") of the
official Xiaomi Home app doing a weigh-in. See README.md for the full
process.

Usage: python3 parse_btsnoop.py <path> <target_bdaddr like AA:BB:CC:DD:EE:FF>
"""
import struct
import sys

ATT_OPCODES = {
    0x01: "Error Response",
    0x02: "Exchange MTU Request",
    0x03: "Exchange MTU Response",
    0x04: "Find Information Request",
    0x05: "Find Information Response",
    0x06: "Find By Type Value Request",
    0x07: "Find By Type Value Response",
    0x08: "Read By Type Request",
    0x09: "Read By Type Response",
    0x0A: "Read Request",
    0x0B: "Read Response",
    0x0C: "Read Blob Request",
    0x0D: "Read Blob Response",
    0x0E: "Read Multiple Request",
    0x0F: "Read Multiple Response",
    0x10: "Read By Group Type Request",
    0x11: "Read By Group Type Response",
    0x12: "Write Request",
    0x13: "Write Response",
    0x16: "Prepare Write Request",
    0x17: "Prepare Write Response",
    0x18: "Execute Write Request",
    0x19: "Execute Write Response",
    0x1B: "Handle Value Notification",
    0x1D: "Handle Value Indication",
    0x1E: "Handle Value Confirmation",
    0x52: "Write Command",
    0xD2: "Signed Write Command",
}


def parse_btsnoop(path, target_addr):
    target_addr_bytes = bytes(reversed([int(b, 16) for b in target_addr.split(":")]))
    handle_to_addr = {}
    target_handles = set()

    with open(path, "rb") as f:
        magic = f.read(8)
        assert magic == b"btsnoop\x00", f"bad magic: {magic}"
        version, datalink = struct.unpack(">II", f.read(8))
        print(f"btsnoop version={version} datalink={datalink}")

        count = 0
        while True:
            header = f.read(24)
            if len(header) < 24:
                break
            orig_len, incl_len, flags, drops, ts = struct.unpack(">IIIIq", header)
            data = f.read(incl_len)
            count += 1
            if len(data) < 1:
                continue

            pkt_type = data[0]
            payload = data[1:]

            # HCI Event (0x04): look for LE Meta Event (0x3E) connection complete
            if pkt_type == 0x04 and len(payload) >= 2:
                event_code = payload[0]
                if event_code == 0x3E and len(payload) >= 3:
                    subevent = payload[2]
                    if subevent in (0x01, 0x0A):  # LE Connection Complete / Enhanced
                        # status(1) handle(2) role(1) addr_type(1) addr(6) ...
                        try:
                            status = payload[3]
                            handle = struct.unpack("<H", payload[4:6])[0]
                            # payload[6] = Role, payload[7] = Peer Address Type, then 6-byte address
                            addr = payload[8:14]
                            handle_to_addr[handle] = addr
                            if addr == target_addr_bytes:
                                target_handles.add(handle)
                                print(f"[{count}] LE Connection Complete: handle={handle} addr={addr.hex()} status={status} <-- TARGET")
                            else:
                                print(f"[{count}] LE Connection Complete: handle={handle} addr={addr.hex()} status={status}")
                        except Exception:
                            pass
                elif event_code == 0x05:  # Disconnection Complete
                    if len(payload) >= 4:
                        handle = struct.unpack("<H", payload[2:4])[0]
                        if handle in target_handles:
                            print(f"[{count}] Disconnection Complete: handle={handle}")

            # ACL Data (0x02): handle(2, lower 12 bits) + flags, length(2), then L2CAP
            elif pkt_type == 0x02 and len(payload) >= 4:
                handle_and_flags = struct.unpack("<H", payload[0:2])[0]
                handle = handle_and_flags & 0x0FFF
                acl_len = struct.unpack("<H", payload[2:4])[0]
                l2cap_data = payload[4:4 + acl_len]
                if len(l2cap_data) < 4:
                    continue
                l2cap_len, cid = struct.unpack("<HH", l2cap_data[0:4])
                att_data = l2cap_data[4:4 + l2cap_len]
                if cid == 0x0004 and att_data and handle in target_handles:  # ATT fixed channel
                    opcode = att_data[0]
                    opcode_name = ATT_OPCODES.get(opcode, f"unknown(0x{opcode:02x})")
                    direction = "SENT" if (flags & 0x01) == 0 else "RECV"
                    print(f"[{count}] handle={handle} {direction} ATT {opcode_name}: {att_data.hex()}")

    print(f"\nTotal records: {count}")
    print(f"Target connection handles seen: {target_handles}")


if __name__ == "__main__":
    parse_btsnoop(sys.argv[1], sys.argv[2])
