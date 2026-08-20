from __future__ import annotations

import asyncio
import dataclasses
import datetime
import os
import typing

from .protocol import Context, Outcome, Result, State, decode_job, encode_result


class Checker(typing.Protocol):
    async def put(self, context: Context) -> State: ...
    async def get(self, context: Context) -> None: ...
    async def check(self, context: Context) -> None: ...


@dataclasses.dataclass(frozen=True)
class RunnerConfig:
    nats_url: str
    service: str
    durable: str
    concurrency: int = 16
    fetch_batch: int = 16


@dataclasses.dataclass(frozen=True)
class Execution:
    result: Result
    started: datetime.datetime
    completed: datetime.datetime


async def execute_checker(checker: Checker, context: Context) -> Execution:
    """Execute one checker job with the same semantics used by the NATS runner."""
    started = datetime.datetime.now(datetime.UTC)
    timeout = max(0.0, (context.deadline - started).total_seconds())
    try:
        async with asyncio.timeout(timeout):
            if context.operation == "PUT":
                state = await checker.put(context)
            elif context.operation == "GET":
                await checker.get(context)
                state = None
            else:
                await checker.check(context)
                state = None
        result = Result(outcome=Outcome.SUCCESS, state=state)
    except TimeoutError:
        result = Result(outcome=Outcome.CHECKER_FAILURE, detail_code="timeout")
    except Exception as error:
        try:
            outcome = Outcome(getattr(error, "outcome", Outcome.CHECKER_FAILURE))
        except ValueError:
            outcome = Outcome.CHECKER_FAILURE
        detail = getattr(error, "detail_code", type(error).__name__.lower())
        result = Result(outcome=outcome, detail_code=str(detail))
    completed = datetime.datetime.now(datetime.UTC)
    return Execution(result=result, started=started, completed=completed)


class Runner:
    def __init__(self, config: RunnerConfig, checker: Checker) -> None:
        if config.concurrency <= 0 or config.fetch_batch <= 0:
            raise ValueError("checker concurrency and batch size must be positive")
        self._config = config
        self._checker = checker
        self._semaphore = asyncio.Semaphore(config.concurrency)

    async def run(self) -> None:
        import nats

        connection = await nats.connect(self._config.nats_url, name=f"vad-checker-{self._config.service}")
        try:
            jetstream = connection.jetstream()
            subscription = await jetstream.pull_subscribe(
                f"checker.{self._config.service}.jobs",
                durable=self._config.durable,
                stream="VAD_CHECKERS",
            )
            while True:
                try:
                    messages = await subscription.fetch(self._config.fetch_batch, timeout=1)
                except (nats.errors.TimeoutError, TimeoutError):
                    continue
                async with asyncio.TaskGroup() as group:
                    for message in messages:
                        group.create_task(self._handle(jetstream, message))
        finally:
            await connection.drain()

    async def _handle(self, jetstream: typing.Any, message: typing.Any) -> None:
        async with self._semaphore:
            try:
                context = decode_job(message.data)
            except (ValueError, UnicodeError):
                await message.term()
                return
            execution = await execute_checker(self._checker, context)
            payload = encode_result(
                context,
                execution.result,
                execution.started,
                execution.completed,
            )
            await jetstream.publish(
                "checker.results",
                payload,
                headers={"Nats-Msg-Id": f"{context.job_id}:{context.attempt}:result"},
            )
            await message.ack_sync()


def serve(checker: Checker) -> None:
    """Run a checker using deployment-provided runtime configuration."""
    service = os.environ.get("VAD_CHECKER_SERVICE", "")
    nats_url = os.environ.get("VAD_NATS_URL", "")
    if not service or not nats_url:
        raise RuntimeError("checker runtime did not provide service or NATS configuration")
    durable = os.environ.get("VAD_CHECKER_DURABLE", f"vad-checker-{service}")
    asyncio.run(Runner(RunnerConfig(nats_url=nats_url, service=service, durable=durable), checker).run())
