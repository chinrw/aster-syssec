from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aster_syssec.config import load_registry
from aster_syssec.inventory import InventoryBuilder
from aster_syssec.routing import TrackRouter
from tests.helpers import write_fixture


class TrackRouterTests(unittest.TestCase):
    def test_syscall_membership_combines_name_and_handler_path(self) -> None:
        router = TrackRouter(load_registry())

        tracks = router.syscall_tracks(
            "not-configured-by-name",
            "kernel/core/src/syscall/recvmsg.rs",
        )

        self.assertIn("abi-integer-layout", tracks)
        self.assertIn("socket-cmsg-iovec", tracks)

    def test_candidate_route_prefers_specific_context_for_protocol_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = write_fixture(Path(tmp))
            registry = load_registry()
            catalog = InventoryBuilder(root, registry).build()
            router = TrackRouter(registry, catalog)

        route = router.candidate_route(
            rule_id="LOCK-GUARD-ACROSS-BLOCKING",
            preferred_track="fd-object-lifetime",
            symbol="sys_futex",
            path="kernel/core/src/syscall/futex.rs",
        )

        self.assertEqual(route.primary, "process-signal-futex")
        self.assertIn("fd-object-lifetime", route.related)
        self.assertIn("abi-integer-layout", route.related)

    def test_selection_inputs_are_owned_by_the_router(self) -> None:
        router = TrackRouter(load_registry())

        selection = router.selection(["socket-cmsg-iovec"])

        self.assertIn("recvmsg", selection.syscalls)
        self.assertIn("kernel/core/src/net/socket", selection.source_roots)


if __name__ == "__main__":
    unittest.main()
