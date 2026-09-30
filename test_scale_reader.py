"""
Tests for scale_reader.py against a simulated scale.

FakeScale implements the scale's side of the protocol as observed in the
decrypted Xiaomi Home app captures (see scale_reader.py's docstring and
decode_btsnoop.py): MTU probe, miauth login, direct/framed values, and the
MIoT actions/events. The weigh-in data is synthetic.

Run from this directory: python -m unittest test_scale_reader -v
(needs this folder's requirements.txt installed; no Bluetooth needed)
"""
import asyncio
import hashlib
import hmac
import json
import os
import struct
import time
import unittest
from types import SimpleNamespace
from unittest import mock

import httpx

import scale_reader
from scale_reader import (
    CMD_LOGIN,
    LOGIN_OK,
    OP_ACTION,
    OP_EVENT,
    OP_HELLO,
    OP_RESULT,
    RCV_ACK,
    RCV_OK,
    RCV_RDY,
    T_STR,
    T_U8,
    T_U16,
    UUIDS,
    aes_ccm_decrypt,
    aes_ccm_encrypt,
    decode_message,
    derive_session_keys,
    encode_message,
    param,
)

TOKEN = bytes.fromhex("00112233445566778899aabb")


def result(tid, *params):
    body = b"\x00\x00" + (bytes([len(params)]) + b"".join(params) if params else b"")
    return encode_message(tid, OP_RESULT, body)


def event(tid, siid, eiid, *params):
    return encode_message(tid, OP_EVENT, bytes([siid, eiid, 0, len(params)]) + b"".join(params))


class FakeScale:
    """State that survives connections: stored weigh-ins, clock, etc."""

    def __init__(self, stored=(), live=(), stall_logins=0, max_value=244, hang_up_after=None):
        self.stored = dict(stored)  # record_no -> (weight_raw, ts)
        self.next_no = max(self.stored, default=0) + 1
        # Weigh-ins that happen after login, one after another: each a list
        # of live weights (1/100 kg), the last one being the final weight.
        self.live = list(live)
        self.hang_up_after = hang_up_after  # seconds after login
        self.stall_logins = stall_logins
        self.max_value = max_value
        self.claimed = []
        self.connections = 0
        self.clock = None
        self.profile = None
        self.errors = []


class FakeChar:
    def __init__(self, name, uuid, handle):
        self.name, self.uuid, self.handle = name, uuid, handle


class FakeServices:
    def __init__(self):
        self.chars = {uuid: FakeChar(name, uuid, 0x10 + i) for i, (name, uuid) in enumerate(UUIDS.items())}

    def get_characteristic(self, uuid):
        return self.chars.get(uuid)


class FakeBackend:
    async def _acquire_mtu(self):
        pass


class FakeClient:
    """Stands in for bleak.BleakClient; one instance per connection."""

    scale: FakeScale = None

    def __init__(self, device, disconnected_callback=None, timeout=None):
        self.callback = disconnected_callback
        self.services = FakeServices()
        self._backend = FakeBackend()
        self.handlers = {}
        self.device = None

    async def __aenter__(self):
        self.scale.connections += 1
        self.device = DeviceSide(self.scale, self)
        return self

    async def __aexit__(self, *exc):
        self.device.task.cancel()
        if self.callback:
            self.callback(self)

    def hang_up(self):
        """The scale closing the connection itself."""
        self.device.task.cancel()
        if self.callback:
            self.callback(self)
            self.callback = None

    async def start_notify(self, char, callback):
        self.handlers[char.name] = (char, callback)

    async def write_gatt_char(self, char, data, response=None):
        self.device.inbox[char.name].put_nowait(bytes(data))

    def notify(self, name, data):
        if name in self.handlers:
            char, callback = self.handlers[name]
            asyncio.get_running_loop().call_soon(callback, char, bytearray(data))


class DeviceSide:
    """The scale's end of one connection."""

    def __init__(self, scale: FakeScale, client: FakeClient):
        self.scale = scale
        self.client = client
        self.inbox = {name: asyncio.Queue() for name in UUIDS}
        self.keys = None
        self.dev_ctr = 1
        self.tid = 100
        self.prop_lock = asyncio.Lock()
        self.task = asyncio.create_task(self.run())

    async def get(self, name):
        return await asyncio.wait_for(self.inbox[name].get(), 5)

    async def recv_framed(self, name):
        header = await self.get(name)
        assert header[:3] == b"\x00\x00\x00" and len(header) == 6, header.hex()
        count = struct.unpack("<H", header[4:6])[0]
        self.client.notify(name, RCV_RDY)
        data = b""
        for no in range(1, count + 1):
            parcel = await self.get(name)
            assert len(parcel) <= self.scale.max_value, "parcel larger than the scale accepts"
            assert struct.unpack("<H", parcel[:2])[0] == no
            data += parcel[2:]
        self.client.notify(name, RCV_OK)
        return header[3], data

    async def send_value(self, name, tag, data):
        if len(data) + 4 <= self.scale.max_value:
            self.client.notify(name, bytes([0, 0, 2, tag]) + data)
            assert await self.get(name) == RCV_ACK
            return
        chunk = self.scale.max_value - 2
        parcels = [data[i : i + chunk] for i in range(0, len(data), chunk)]
        self.client.notify(name, bytes([0, 0, 0, tag]) + struct.pack("<H", len(parcels)))
        assert await self.get(name) == RCV_RDY
        for no, part in enumerate(parcels, 1):
            self.client.notify(name, struct.pack("<H", no) + part)
        assert await self.get(name) == RCV_OK

    async def push(self, pt):
        async with self.prop_lock:
            ctr = self.dev_ctr
            self.dev_ctr += 1
            ct = aes_ccm_encrypt(self.keys["dev_key"], self.keys["dev_iv"], ctr, pt)
            await self.send_value("PROP", 0, struct.pack("<H", ctr) + ct)

    async def run(self):
        try:
            await self._run()
        except asyncio.CancelledError:
            raise
        except Exception as err:  # surfaced by the tests
            self.scale.errors.append(repr(err))

    async def _run(self):
        scale = self.scale
        assert await self.get("LOGIN") == b"\xa4"
        self.client.notify("AUTH", bytes.fromhex("0000040006f2"))
        assert await self.get("AUTH") == bytes.fromhex("0000050006f2")
        probe = b"\xf2" * (scale.max_value - 4)
        self.client.notify("AUTH", bytes.fromhex("00000401") + probe)
        assert await self.get("AUTH") == bytes.fromhex("00000501") + probe

        assert await self.get("LOGIN") == CMD_LOGIN
        if scale.stall_logins:
            scale.stall_logins -= 1
            await asyncio.sleep(3600)  # never answers, like the flaky real logins

        tag, rand_key = await self.recv_framed("AUTH")
        assert tag == 0x0B and len(rand_key) == 16
        remote_key = os.urandom(16)
        self.keys = derive_session_keys(TOKEN, rand_key, remote_key)
        await self.send_value("AUTH", 0x0D, remote_key)
        await self.send_value("AUTH", 0x0C, hmac.new(self.keys["dev_key"], remote_key + rand_key, hashlib.sha256).digest())
        tag, login_info = await self.recv_framed("AUTH")
        assert tag == 0x0A
        assert login_info == hmac.new(self.keys["app_key"], rand_key + remote_key, hashlib.sha256).digest()
        self.client.notify("LOGIN", LOGIN_OK)
        if scale.hang_up_after is not None:
            asyncio.get_running_loop().call_later(scale.hang_up_after, self.client.hang_up)

        while True:
            _, data = await self.recv_framed("CMD")
            ctr = struct.unpack("<H", data[:2])[0]
            msg = decode_message(aes_ccm_decrypt(self.keys["app_key"], self.keys["app_iv"], ctr, data[2:]))
            await self.handle(msg)

    async def handle(self, msg):
        scale = self.scale
        if msg.op == OP_HELLO:
            await self.push(encode_message(msg.tid, OP_HELLO))
        elif msg.op == OP_ACTION and (msg.siid, msg.iid) == (7, 1):
            scale.profile = json.loads(msg.params[1])
            scale.clock = scale.profile["time"]
            await self.push(result(
                msg.tid, param(2, T_U8, len(scale.stored)), param(3, T_STR, "59212/TEST"),
                param(4, T_STR, "AA:BB:CC:DD:EE:FF"), param(5, T_STR, "2.1.2_0008.0010"), param(6, T_U8, 0),
            ))
            if scale.live:
                asyncio.create_task(self.weigh_ins(scale.live))
                scale.live = []
        elif msg.op == OP_ACTION and (msg.siid, msg.iid) == (6, 1):
            await self.push(result(msg.tid, param(3, T_U8, len(scale.stored))))
            if scale.stored:
                text = "_".join(f"{no},0,0,{w},2,{ts}" for no, (w, ts) in sorted(scale.stored.items()))
                self.tid += 1
                await self.push(event(self.tid, 6, 1, param(1, T_STR, text)))
        elif msg.op == OP_ACTION and (msg.siid, msg.iid) == (6, 2):
            for no in msg.params[2].split(","):
                scale.stored.pop(int(no), None)
            await self.push(result(msg.tid))
        elif msg.op == OP_ACTION and (msg.siid, msg.iid) == (4, 3):
            scale.claimed.append((msg.params[1], msg.params[2], msg.params[8]))
            await self.push(result(msg.tid))
        else:
            raise AssertionError(f"unexpected {msg}")

    async def weigh_ins(self, weigh_ins):
        for weights in weigh_ins:
            await asyncio.sleep(0.2)
            await self.weigh_in(weights)

    async def weigh_in(self, weights):
        for i, w in enumerate(weights):
            self.tid += 1
            stable = int(i == len(weights) - 1)
            await self.push(event(self.tid, 5, 3, param(1, T_U8, 0), param(2, T_U8, stable), param(3, T_U16, w)))
            await asyncio.sleep(0.05)
        ts = int(time.time())
        self.tid += 1
        await self.push(event(self.tid, 5, 4, param(4, T_STR, f"0,0,{weights[-1]},2,{ts}")))
        await asyncio.sleep(0.5)
        if not any(c[2] == weights[-1] for c in self.scale.claimed):
            self.scale.stored[self.scale.next_no] = (weights[-1], ts)  # unclaimed: kept in memory
            self.scale.next_no += 1


class FakeBackendApi:
    """Stands in for the webhook (dedupes on recorded_at + weight_kg)."""

    def __init__(self, fail=False):
        self.fail = fail
        self.entries = []

    def handler(self, request):
        assert request.headers["Authorization"] == "Bearer test-token"
        if self.fail:
            return httpx.Response(500, json={"error": "down"})
        body = json.loads(request.content)
        if any(e["recorded_at"] == body["recorded_at"] and e["weight_kg"] == body["weight_kg"] for e in self.entries):
            return httpx.Response(200, json={**body, "duplicate": True})
        self.entries.append(body)
        return httpx.Response(201, json=body)


class ScannerTestCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        patches = {
            "XIAOMI_TOKEN": TOKEN,
            "WEBHOOK_URL": "http://webhook.test/weigh-ins",
            "WEBHOOK_TOKEN": "test-token",
            "KEEP_ON_SCALE": False,
            "XIAOMI_MAC": "AA:BB:CC:DD:EE:FF",
            "BleakClient": FakeClient,
            "STEP_TIMEOUT_S": 0.5,
            "RESULT_TIMEOUT_S": 1,
            "RECORDS_TIMEOUT_S": 1,
            "LIVE_START_S": 1,
            "LIVE_IDLE_S": 1,
        }
        for name, value in patches.items():
            p = mock.patch.object(scale_reader, name, value)
            p.start()
            self.addCleanup(p.stop)

    async def make_reader(self, api):
        http = httpx.AsyncClient(transport=httpx.MockTransport(api.handler))
        self.addAsyncCleanup(http.aclose)
        return scale_reader.Reader(http)


class CodecTests(unittest.TestCase):
    def test_message_roundtrip(self):
        pt = encode_message(7, OP_ACTION, bytes([6, 2, 1]) + param(2, T_STR, "11,12"))
        self.assertEqual(pt[:2], b"\x11\x20")  # 0x2000 | total length
        msg = decode_message(pt)
        self.assertEqual((msg.op, msg.siid, msg.iid, msg.params), (OP_ACTION, 6, 2, {2: "11,12"}))

    def test_captured_messages(self):
        # Decrypted plaintexts in the exact format of the Xiaomi app captures
        # (the weight changed to 90.00 kg).
        live = decode_message(bytes.fromhex("19200f00070503000301000110000200011001030002302823"))
        self.assertEqual((live.op, live.siid, live.iid, live.params), (OP_EVENT, 5, 3, {1: 0, 2: 1, 3: 9000}))
        count = decode_message(bytes.fromhex("0d200400060000010300011012"))
        self.assertEqual((count.op, count.status, count.params), (OP_RESULT, 0, {3: 18}))
        done = decode_message(bytes.fromhex("07200c00060000"))
        self.assertEqual((done.op, done.status, done.params), (OP_RESULT, 0, {}))

    def test_long_message_length_header(self):
        text = "_".join(f"{n},0,0,{8000 + n},2,{1789700000 + n}" for n in range(1, 21))
        pt = event(5, 6, 1, param(1, T_STR, text))
        self.assertGreater(len(pt), 255)
        self.assertEqual(struct.unpack("<H", pt[:2])[0], 0x2000 | len(pt))
        records = scale_reader.parse_stored_records(decode_message(pt).params[1])
        self.assertEqual(len(records), 20)
        self.assertEqual((records[0].record_no, records[0].weight_kg, records[0].timestamp), (1, 80.01, 1789700001))

    def test_finished_weigh_in(self):
        w = scale_reader.parse_weigh_in("1,1,9000,0,1789901471", numbered=False)
        self.assertEqual((w.weight_kg, w.timestamp, w.record_no), (90.0, 1789901471, None))
        self.assertIsNone(scale_reader.parse_weigh_in("garbage", numbered=False))


class SessionTests(ScannerTestCase):
    async def test_syncs_stored_weigh_ins_and_live_weigh_in(self):
        now = int(time.time())
        stored = {n: (8000 + n, now - 86400 + n * 60) for n in range(11, 29)}  # 18, like the capture
        FakeClient.scale = scale = FakeScale(stored=stored, live=[[8010, 8030, 8025]])
        api = FakeBackendApi()
        reader = await self.make_reader(api)

        await scale_reader.run_session(object(), reader)

        self.assertEqual(scale.errors, [])
        self.assertEqual(scale.stored, {}, "stored weigh-ins should be deleted after delivering")
        self.assertEqual(len(api.entries), 19)
        self.assertEqual(api.entries[0], {"weight_kg": 80.11, "recorded_at": scale_reader.datetime.fromtimestamp(stored[11][1], scale_reader.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
        self.assertEqual(api.entries[-1]["weight_kg"], 80.25)
        self.assertEqual(scale.claimed, [(scale_reader.PROFILE_MEMBER_ID, 1, 8025)])
        self.assertAlmostEqual(scale.clock, time.time(), delta=5)
        self.assertEqual(reader.last_weight_kg, 80.25)

    async def test_several_weigh_ins_in_one_session(self):
        # Stepping on again (holding something) before the scale goes back
        # to sleep: all of them should arrive, not just the first.
        FakeClient.scale = scale = FakeScale(live=[[9000, 9120], [9500, 9650], [10200]])
        api = FakeBackendApi()
        collected = await scale_reader.run_session(object(), await self.make_reader(api))
        self.assertEqual(scale.errors, [])
        self.assertEqual(collected, 3)
        self.assertEqual([e["weight_kg"] for e in api.entries], [91.2, 96.5, 102.0])
        self.assertEqual([c[2] for c in scale.claimed], [9120, 9650, 10200])

    async def test_scale_hanging_up_ends_session_normally(self):
        FakeClient.scale = scale = FakeScale(live=[[9120]], hang_up_after=0.8)
        api = FakeBackendApi()
        with mock.patch.object(scale_reader, "LIVE_IDLE_S", 5):
            collected = await scale_reader.sync_wakeup(object(), await self.make_reader(api))
        self.assertEqual(collected, 1)
        self.assertEqual(scale.connections, 1, "a hang-up after syncing is not a failure to retry")
        self.assertEqual([e["weight_kg"] for e in api.entries], [91.2])

    async def test_keep_on_scale_leaves_everything_in_place(self):
        stored = {1: (9000, int(time.time()) - 3600)}
        FakeClient.scale = scale = FakeScale(stored=dict(stored), live=[[9120]])
        api = FakeBackendApi()
        with mock.patch.object(scale_reader, "KEEP_ON_SCALE", True):
            await scale_reader.run_session(object(), await self.make_reader(api))
        await asyncio.sleep(0.7)  # FakeScale keeps an unclaimed weigh-in after 0.5s
        self.assertEqual(scale.errors, [])
        self.assertEqual([e["weight_kg"] for e in api.entries], [90.0, 91.2])
        self.assertEqual(scale.claimed, [])
        self.assertEqual(len(scale.stored), 2)

    async def test_without_webhook_prints_json_lines(self):
        FakeClient.scale = scale = FakeScale(stored={1: (9000, 1790000000)})
        with (
            mock.patch.object(scale_reader, "WEBHOOK_URL", ""),
            mock.patch("builtins.print") as printed,
        ):
            await scale_reader.run_session(object(), await self.make_reader(FakeBackendApi()))
        printed.assert_called_once_with('{"weight_kg": 90.0, "recorded_at": "2026-09-21T14:13:20Z"}', flush=True)
        self.assertEqual(scale.stored, {})

    async def test_small_mtu_uses_multi_parcel_values(self):
        FakeClient.scale = scale = FakeScale(stored={1: (9010, int(time.time()) - 60)}, max_value=20)
        api = FakeBackendApi()
        await scale_reader.run_session(object(), await self.make_reader(api))
        self.assertEqual(scale.errors, [])
        self.assertEqual([e["weight_kg"] for e in api.entries], [90.1])

    async def test_failed_delivery_leaves_weigh_ins_on_scale(self):
        stored = {1: (9000, int(time.time()) - 3600)}
        FakeClient.scale = scale = FakeScale(stored=dict(stored))
        await scale_reader.run_session(object(), await self.make_reader(FakeBackendApi(fail=True)))
        self.assertEqual(scale.errors, [])
        self.assertEqual(scale.stored, stored)

    async def test_unclaimed_weigh_in_is_collected_later_without_duplicate(self):
        FakeClient.scale = scale = FakeScale(live=[[9100]])
        api = FakeBackendApi(fail=True)  # live weigh-in fails to deliver, so it isn't claimed
        await scale_reader.run_session(object(), await self.make_reader(api))
        await asyncio.sleep(0.7)  # FakeScale keeps an unclaimed weigh-in after 0.5s
        self.assertEqual(len(scale.stored), 1)
        api.fail = False
        await scale_reader.run_session(object(), await self.make_reader(api))
        self.assertEqual([e["weight_kg"] for e in api.entries], [91.0])
        self.assertEqual(scale.stored, {})

    async def test_stalled_login_is_retried(self):
        FakeClient.scale = scale = FakeScale(stored={1: (9000, int(time.time()) - 60)}, stall_logins=1)
        api = FakeBackendApi()
        with mock.patch.object(scale_reader, "find_scale", mock.AsyncMock(return_value=(object(), None))):
            ok = await scale_reader.sync_wakeup(object(), await self.make_reader(api))
        self.assertTrue(ok)
        self.assertEqual(scale.connections, 2)
        self.assertEqual(len(api.entries), 1)


def adv(counter):
    beacon = bytes.fromhex("1059cb4d") + bytes([counter]) + bytes.fromhex("ffeeddccbbaa")
    return SimpleNamespace(rssi=-60, service_data={scale_reader.MIBEACON_UUID: beacon})


class WakeUpPolicyTests(ScannerTestCase):
    async def run_main(self, sightings, collected=(), stored_while_connecting=()):
        """Feed main() a scripted sequence of scan results -- None = scale not
        seen, an int = seen with that MiBeacon frame counter -- and return how
        many syncs it started. `collected` = what each sync reports;
        `stored_while_connecting` = per sync, how many of the stored weigh-ins
        it collected are newer than the advertisement that triggered it."""
        script = iter(sightings)
        results = iter(collected)
        stored_later = iter(stored_while_connecting)
        syncs = []

        async def fake_find_scale(timeout):
            try:
                counter = next(script)
            except StopIteration:
                raise asyncio.CancelledError
            return (None, None) if counter is None else (object(), adv(counter))

        async def fake_sync(device, reader):
            syncs.append(device)
            reader.stored_timestamps += [int(time.time()) + 5] * next(stored_later, 0)
            return next(results, 1)

        with (
            mock.patch.object(scale_reader, "find_scale", fake_find_scale),
            mock.patch.object(scale_reader, "sync_wakeup", fake_sync),
            mock.patch.object(scale_reader, "AWAKE_RECHECK_S", 0),
        ):
            with self.assertRaises(asyncio.CancelledError):
                await scale_reader.main()
        return len(syncs)

    async def test_one_sync_per_wake_up(self):
        self.assertEqual(await self.run_main([3] * 30), 1)
        self.assertEqual(await self.run_main([None, 3, 3, 3, None, None, 4, 4]), 2)

    async def test_counter_change_while_awake_syncs_again(self):
        # wake-up sync at counter 3, then two more weigh-ins get stored
        self.assertEqual(await self.run_main([3, 3, 3, 4, 4, 4, 5, 5]), 3)

    async def test_weigh_in_stored_right_after_a_sync_is_noticed(self):
        # 2026-09-30: the very first sighting after a session already showed
        # the next weigh-in, and taking that as the baseline missed it.
        self.assertEqual(await self.run_main([7, 8, 8]), 2)

    async def test_weigh_in_stored_while_connecting_is_not_a_new_one(self):
        # Woke at counter 3; the weigh-in finished (stored, counter 4) before
        # the login, and the sync collected it -- 4 is expected afterwards.
        self.assertEqual(await self.run_main([3, 4, 4, 4], stored_while_connecting=[1]), 1)

    async def test_fruitless_counter_sync_stops_following_counter(self):
        # The second (counter-triggered) sync finds nothing: further counter
        # changes in the same wake-up are ignored, until the scale sleeps.
        sightings = [3, 3, 4, 4, 5, 6, 7, None, 8, 8, 9]
        self.assertEqual(await self.run_main(sightings, collected=[1, 0, 1, 1]), 4)

    async def test_exits_when_scanning_keeps_failing(self):
        # e.g. the adapter vanished: exit so Docker restarts the container
        # and its entrypoint reloads the kernel modules.
        async def broken_scan(timeout):
            raise scale_reader.BleakError("No Bluetooth adapters found.")

        with (
            mock.patch.object(scale_reader, "find_scale", broken_scan),
            mock.patch.object(scale_reader, "SCAN_RETRY_S", 0),
            mock.patch.object(scale_reader, "MAX_SCAN_FAILURES", 3),
        ):
            with self.assertRaises(SystemExit):
                await scale_reader.main()

    async def test_resync_if_scale_never_sleeps(self):
        with mock.patch.object(scale_reader, "RESYNC_WHILE_AWAKE_S", 0):
            self.assertEqual(await self.run_main([3] * 3), 3)


if __name__ == "__main__":
    unittest.main()
