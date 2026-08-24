import asyncio
import json
import unittest

from vad_checker import Context, Outcome, State
from vad_checker.integration import (
    IntegrationConfig,
    IntegrationError,
    _duration,
    _gateway_service,
    _redact_logs,
    run_integration,
)


class ServiceError(Exception):
    outcome = Outcome.SERVICE_FAILURE
    detail_code = "ordinary_flow_failed"


class RetainingChecker:
    def __init__(self) -> None:
        self.values = {}
        self.put_attempts = []
        self.checks = 0

    async def put(self, context: Context) -> State:
        key = f"state-{len(self.values)}"
        self.values[key] = context.flag
        self.put_attempts.append((context.job_id, context.attempt))
        return State(public={"id": key}, private={"token": f"token-{key}"})

    async def get(self, context: Context) -> None:
        if self.values.get(context.public["id"]) != context.flag:
            raise AssertionError("missing flag")

    async def check(self, _context: Context) -> None:
        self.checks += 1


class FailingChecker(RetainingChecker):
    async def check(self, _context: Context) -> None:
        raise ServiceError


class LeakingChecker(RetainingChecker):
    async def put(self, context: Context) -> State:
        return State(public={"value": context.flag}, private={})


class InvalidStateChecker(RetainingChecker):
    async def put(self, _context: Context):
        return {"public": {}, "private": {}}


class SlowChecker(RetainingChecker):
    async def check(self, _context: Context) -> None:
        await asyncio.sleep(0.05)


class IntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_runs_retry_and_retention_contract_for_every_store(self) -> None:
        checker = RetainingChecker()
        messages = []
        report = await run_integration(
            checker,
            IntegrationConfig("notes", ("private_notes", "drafts"), "127.0.0.1", run_id="test"),
            report=messages.append,
        )

        self.assertEqual(report.stores, ("private_notes", "drafts"))
        self.assertEqual(checker.checks, 2)
        self.assertEqual(len(checker.put_attempts), 6)
        self.assertEqual(checker.put_attempts[:2], [
            ("integration:test:private_notes:put:a", 1),
            ("integration:test:private_notes:put:a", 2),
        ])
        self.assertEqual(messages[-1], "CHECK after stores: ok")
        state_lines = [message for message in messages if message.startswith("STATE ")]
        self.assertEqual(len(state_lines), 2)
        payload = json.loads(state_lines[0].removeprefix("STATE "))
        self.assertEqual(payload["store"], "private_notes")
        self.assertEqual(payload["public"], {"id": "state-2"})
        self.assertEqual(payload["flag"], "CTF{VAD_INTEGRATION_private_notes_test_B}")

    async def test_reports_production_outcome_and_detail(self) -> None:
        with self.assertRaisesRegex(
            IntegrationError,
            r"CHECK service failed: SERVICE_FAILURE \(ordinary_flow_failed\)",
        ):
            await run_integration(
                FailingChecker(),
                IntegrationConfig(
                    "notes", ("private_notes",), "127.0.0.1", startup_timeout=0.001
                ),
                report=None,
            )

    async def test_rejects_flag_in_state(self) -> None:
        with self.assertRaisesRegex(IntegrationError, "leaked its flag in public state"):
            await run_integration(
                LeakingChecker(),
                IntegrationConfig("notes", ("private_notes",), "127.0.0.1"),
                report=None,
            )

    async def test_rejects_invalid_put_state(self) -> None:
        with self.assertRaisesRegex(IntegrationError, "returned an invalid result"):
            await run_integration(
                InvalidStateChecker(),
                IntegrationConfig("notes", ("private_notes",), "127.0.0.1"),
                report=None,
            )

    async def test_enforces_production_deadline(self) -> None:
        with self.assertRaisesRegex(
            IntegrationError,
            r"CHECK service failed: SERVICE_FAILURE \(service_timeout\)",
        ):
            await run_integration(
                SlowChecker(),
                IntegrationConfig(
                    "notes",
                    ("private_notes",),
                    "127.0.0.1",
                    timeout=0.001,
                    startup_timeout=0.002,
                ),
                report=None,
            )


class ProjectDiscoveryTests(unittest.TestCase):
    def test_parses_manifest_duration(self) -> None:
        self.assertEqual(_duration("250ms"), 0.25)
        self.assertEqual(_duration("45s"), 45.0)
        self.assertEqual(_duration("1m"), 60.0)

    def test_finds_single_gateway_for_manifest_ports(self) -> None:
        gateway = _gateway_service(
            {
                "notes-app": {"ports": [{"target": 10001, "protocol": "tcp"}]},
                "database": {"ports": []},
            },
            (10001,),
        )
        self.assertEqual(gateway, "notes-app")

    def test_rejects_ports_split_across_containers(self) -> None:
        with self.assertRaisesRegex(IntegrationError, "one Compose gateway"):
            _gateway_service(
                {
                    "web": {"ports": [{"target": 10001}]},
                    "socket": {"ports": [{"target": 10002}]},
                },
                (10001, 10002),
            )

    def test_redacts_tokens_from_service_logs(self) -> None:
        self.assertEqual(
            _redact_logs('GET /ws?token=secret-value HTTP/1.1'),
            'GET /ws?token=<redacted> HTTP/1.1',
        )


if __name__ == "__main__":
    unittest.main()
