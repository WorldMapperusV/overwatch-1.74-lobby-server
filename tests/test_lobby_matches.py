import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ow174.accounts.profile import Profile
from ow174.jam.codec import Schemas
from ow174.lobby.handlers import build_router
from ow174.lobby.session import Session
from ow174.matches.runtime import MatchManager

QUEUE = 0x1C6EC712
CUSTOM = 0xA6E53896
GAME_STATE = 0x1CFB43CD
GAME_STATE_ACK = 0x888716D3
HANDOFF = 0x074DAD18


class LobbyMatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.matches = MatchManager(Path(self.tmp.name), base_port=0)
        self.addCleanup(self.matches.close)
        self.schemas = Schemas()
        account = SimpleNamespace(name="Alpha", profile=Profile(player_name="Alpha"), account_lo=1)
        party = SimpleNamespace(queue=None, roles={}, members=[account])
        server = SimpleNamespace(
            matches=self.matches,
            schemas=self.schemas,
            state_lock=threading.RLock(),
            router=build_router(),
            recorder=SimpleNamespace(record=lambda *args: None),
            social=SimpleNamespace(party_of=lambda account: party),
            notify_party=lambda party: None,
            content=SimpleNamespace(arcade=SimpleNamespace(has_roles=lambda card: False)),
            session_of=lambda account_lo: self.session,
        )
        self.session = Session(server, None, None, 5)
        self.session.account = account
        self.session.logged_in = True
        self.logs = []
        self.sent = []
        self.session.log = lambda message, *args: self.logs.append(message)
        self.session.announce([QUEUE, CUSTOM, GAME_STATE_ACK, GAME_STATE, HANDOFF])
        self.session.send = lambda crc, msg, value: self.sent.append((crc, msg, value)) or True

    def test_captured_practice_request_allocates_real_server(self):
        self.session.dispatch(2, 0, bytes.fromhex("020004000000"))
        states = self.matches.snapshot()
        self.assertEqual(len(states), 1, "24000 must reach the instance allocator")
        self.assertEqual(states[0]["player"], "Alpha")
        self.assertEqual(states[0]["state"], "listening")
        self.assertEqual(len(self.sent), 1)
        crc, msg, value = self.sent[0]
        self.assertEqual((crc, msg), (GAME_STATE, 53000))
        self.assertEqual(value["+0x78"]["+0x60"], 4)
        self.assertEqual(value["+0xE8"], 0)
        self.assertIsNotNone(self.session.practice_state_pending)

    def test_practice_state_ack_sends_transport_credentials(self):
        self.session.dispatch(2, 0, bytes.fromhex("020004000000"))
        port = self.matches.snapshot()[0]["port"]
        body = self.schemas.encode(GAME_STATE_ACK, 52903, {"+0x78": True})
        self.session.dispatch(3, 0, body)
        self.assertIsNone(self.session.practice_state_pending)
        self.assertTrue(any("state 4 acknowledged" in line for line in self.logs))
        self.assertEqual(len(self.sent), 2)
        crc, msg, value = self.sent[1]
        self.assertEqual((crc, msg), (HANDOFF, 20600))
        self.assertIs(value["+0x78"], True)
        self.assertEqual(value["+0x80"]["+0x2C"], port)
        record = value["+0x80"]
        self.assertEqual(record["+0x28"], 2)
        self.assertEqual(bytes(record["+0x2E"][:4]), bytes((127, 0, 0, 1)))
        self.assertEqual(bytes(record["+0x6E"]), bytes(64))
        instance = next(iter(self.matches.instances.values()))
        self.assertEqual(record["+0x18"], int.from_bytes(instance.client_tx_nonce, "little"))
        self.assertEqual(record["+0x20"], int.from_bytes(instance.client_rx_nonce, "little"))
        self.assertEqual(bytes(record["+0xAE"]), instance.client_tx_key)
        self.assertEqual(bytes(record["+0xCE"]), instance.client_rx_key)

    def test_search_and_cancel_messages_start_then_stop_worker(self):
        # Captured Mystery Heroes request and cancellation have identical bodies.
        body = bytes.fromhex(
            "0200000000003006000000000000000000000000000000000000000000000000000000004086f3004486f400"
        )
        self.session.dispatch(1, 0, body)
        self.assertEqual(len(self.matches.snapshot()), 1)
        self.session.dispatch(1, 2, body)
        self.assertEqual(self.matches.snapshot(), [])


if __name__ == "__main__":
    unittest.main()
