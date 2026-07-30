import datetime
import sys
import types
import unittest
from unittest import mock

from vad_checker.runner import Runner, RunnerConfig


class StopRunner(Exception):
    pass


class IdleThenStopSubscription:
    def __init__(self) -> None:
        self.fetches = 0

    async def fetch(self, _batch: int, timeout: int):
        self.fetches += 1
        if self.fetches == 1:
            raise TimeoutError
        raise StopRunner


class FakeJetStream:
    def __init__(self, subscription: IdleThenStopSubscription) -> None:
        self.subscription = subscription

    async def pull_subscribe(self, *_args, **_kwargs):
        return self.subscription


class FakeConnection:
    def __init__(self, jetstream: FakeJetStream) -> None:
        self._jetstream = jetstream
        self.drained = False

    def jetstream(self) -> FakeJetStream:
        return self._jetstream

    async def drain(self) -> None:
        self.drained = True


class RecordingJetStream:
    def __init__(self) -> None:
        self.publishes = []

    async def publish(self, subject, payload, headers):
        self.publishes.append((subject, payload, headers))


class FakeMessage:
    data = b"job"

    def __init__(self) -> None:
        self.acked = False

    async def ack_sync(self) -> None:
        self.acked = True


class PassingChecker:
    async def check(self, _context) -> None:
        return None


class RunnerTests(unittest.IsolatedAsyncioTestCase):
    async def test_idle_builtin_timeout_does_not_stop_runner(self) -> None:
        subscription = IdleThenStopSubscription()
        connection = FakeConnection(FakeJetStream(subscription))

        async def connect(*_args, **_kwargs):
            return connection

        fake_nats = types.SimpleNamespace(
            connect=connect,
            errors=types.SimpleNamespace(TimeoutError=type("NATSTimeoutError", (Exception,), {})),
        )
        runner = Runner(RunnerConfig("nats://example", "fileshare", "durable"), object())
        with mock.patch.dict(sys.modules, {"nats": fake_nats}):
            with self.assertRaises(StopRunner):
                await runner.run()

        self.assertEqual(subscription.fetches, 2)
        self.assertTrue(connection.drained)

    async def test_result_uses_distinct_jetstream_deduplication_id(self) -> None:
        context = types.SimpleNamespace(
            job_id="job-1",
            attempt=2,
            deadline=datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=5),
            operation="CHECK",
        )
        jetstream = RecordingJetStream()
        message = FakeMessage()
        runner = Runner(RunnerConfig("nats://example", "fileshare", "durable"), PassingChecker())

        with mock.patch("vad_checker.runner.decode_job", return_value=context), mock.patch(
            "vad_checker.runner.encode_result", return_value=b"result"
        ):
            await runner._handle(jetstream, message)

        self.assertEqual(
            jetstream.publishes,
            [("checker.results", b"result", {"Nats-Msg-Id": "job-1:2:result"})],
        )
        self.assertTrue(message.acked)


if __name__ == "__main__":
    unittest.main()
