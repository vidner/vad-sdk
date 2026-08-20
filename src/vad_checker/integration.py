from __future__ import annotations

import argparse
import asyncio
import dataclasses
import datetime
import importlib
import inspect
import json
import os
import pathlib
import re
import secrets
import subprocess
import sys
import tempfile
import typing

from .protocol import Context, Outcome, State, encode_result
from .runner import Checker, execute_checker


class IntegrationError(AssertionError):
    """Raised when a checker fails the service integration contract."""


class _ReportedIntegrationError(IntegrationError):
    pass


StateValidator = typing.Callable[[str, State], None]
Reporter = typing.Callable[[str], None]


@dataclasses.dataclass(frozen=True)
class IntegrationConfig:
    service: str
    stores: tuple[str, ...]
    host: str
    flag_prefix: str = "CTF"
    timeout: float = 60.0
    startup_timeout: float = 60.0
    team: str = "integration-team"
    run_id: str = dataclasses.field(default_factory=lambda: secrets.token_hex(6))

    def __post_init__(self) -> None:
        if not self.service or not self.host or not self.flag_prefix or not self.team:
            raise ValueError("service, host, flag prefix, and team must be non-empty")
        if not self.stores or any(not store for store in self.stores):
            raise ValueError("at least one non-empty store is required")
        if len(set(self.stores)) != len(self.stores):
            raise ValueError("stores must be unique")
        if self.timeout <= 0:
            raise ValueError("integration timeout must be positive")
        if self.startup_timeout <= 0:
            raise ValueError("integration startup timeout must be positive")


@dataclasses.dataclass(frozen=True)
class IntegrationReport:
    service: str
    stores: tuple[str, ...]
    run_id: str


def _context(
    config: IntegrationConfig,
    operation: str,
    job_id: str,
    *,
    attempt: int = 1,
    store: str | None = None,
    flag: str | None = None,
    state: State | None = None,
) -> Context:
    return Context(
        job_id=job_id,
        attempt=attempt,
        operation=operation,
        deadline=datetime.datetime.now(datetime.UTC)
        + datetime.timedelta(seconds=config.timeout),
        game_id=1,
        tick=1,
        service=config.service,
        team=config.team,
        host=config.host,
        store=store,
        flag=flag,
        public=None if state is None else state.public,
        private=None if state is None else state.private,
    )


async def _execute(checker: Checker, context: Context) -> State | None:
    execution = await execute_checker(checker, context)
    try:
        encode_result(
            context,
            execution.result,
            execution.started,
            execution.completed,
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise IntegrationError(
            f"{context.operation} {context.store or 'service'} returned an invalid result: {error}"
        ) from error
    if execution.result.outcome is not Outcome.SUCCESS:
        detail = execution.result.detail_code or "no_detail"
        raise IntegrationError(
            f"{context.operation} {context.store or 'service'} failed: "
            f"{execution.result.outcome.value} ({detail})"
        )
    return execution.result.state


def _validate_state(store: str, flag: str, state: State) -> None:
    for name, value in (("public", state.public), ("private", state.private)):
        encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        if flag in encoded:
            raise IntegrationError(f"PUT {store} leaked its flag in {name} state")


async def run_integration(
    checker: Checker,
    config: IntegrationConfig,
    *,
    validate_state: StateValidator | None = None,
    report: Reporter | None = print,
) -> IntegrationReport:
    """Exercise CHECK and every store's PUT, GET, retry, and retention contract."""

    async def successful_put(context: Context) -> State:
        state = await _execute(checker, context)
        if not isinstance(state, State):
            raise IntegrationError(f"PUT {context.store} did not return State")
        if context.store is None or context.flag is None:
            raise IntegrationError("integration PUT context is missing its store or flag")
        _validate_state(context.store, context.flag, state)
        if validate_state is not None:
            try:
                validate_state(context.store, state)
            except IntegrationError:
                raise
            except Exception as error:
                raise IntegrationError(
                    f"PUT {context.store} failed custom state validation: {error}"
                ) from error
        return state

    startup_deadline = asyncio.get_running_loop().time() + config.startup_timeout
    startup_attempt = 1
    while True:
        try:
            await _execute(
                checker,
                _context(
                    config,
                    "CHECK",
                    f"integration:{config.run_id}:check:before",
                    attempt=startup_attempt,
                ),
            )
            break
        except IntegrationError as error:
            remaining = startup_deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise IntegrationError(f"service did not become ready: {error}") from error
            await asyncio.sleep(min(0.5, remaining))
            startup_attempt += 1
    if report is not None:
        report("CHECK before stores: ok")

    for index, store in enumerate(config.stores, start=1):
        base = f"integration:{config.run_id}:{store}"
        flag = f"{config.flag_prefix}{{VAD_INTEGRATION_{config.run_id}_{index}_A}}"
        put = _context(config, "PUT", f"{base}:put:a", store=store, flag=flag)
        first = await successful_put(put)
        await _execute(
            checker,
            _context(config, "GET", f"{base}:get:a:first", store=store, flag=flag, state=first),
        )

        retried = await successful_put(dataclasses.replace(put, attempt=2))
        await _execute(
            checker,
            _context(config, "GET", f"{base}:get:a:retry", store=store, flag=flag, state=retried),
        )
        await _execute(
            checker,
            _context(config, "GET", f"{base}:get:a:original", store=store, flag=flag, state=first),
        )

        newer_flag = f"{config.flag_prefix}{{VAD_INTEGRATION_{config.run_id}_{index}_B}}"
        newer = await successful_put(
            _context(config, "PUT", f"{base}:put:b", store=store, flag=newer_flag)
        )
        await _execute(
            checker,
            _context(config, "GET", f"{base}:get:b", store=store, flag=newer_flag, state=newer),
        )
        await _execute(
            checker,
            _context(config, "GET", f"{base}:get:a:retained", store=store, flag=flag, state=first),
        )
        if report is not None:
            report(f"{store}: PUT/GET/retry/retention ok")

    await _execute(checker, _context(config, "CHECK", f"integration:{config.run_id}:check:after"))
    if report is not None:
        report("CHECK after stores: ok")
    return IntegrationReport(config.service, config.stores, config.run_id)


@dataclasses.dataclass(frozen=True)
class ProjectConfig:
    root: pathlib.Path
    service: str
    stores: tuple[str, ...]
    flag_prefix: str
    timeout: float
    gateway: str
    service_names: tuple[str, ...]
    published_services: tuple[str, ...]

    @property
    def service_compose(self) -> pathlib.Path:
        return self.root / "services" / self.service / "compose.yaml"

    @property
    def checker_compose(self) -> pathlib.Path:
        return self.root / "checkers" / self.service / "compose.yaml"


def _find_root(start: pathlib.Path) -> pathlib.Path:
    for candidate in (start, *start.parents):
        if (
            (candidate / "game.yaml").is_file()
            and (candidate / "services").is_dir()
            and (candidate / "checkers").is_dir()
        ):
            return candidate
    raise IntegrationError("run from a VAD game repository containing game.yaml")


def _yaml_object(path: pathlib.Path) -> dict[str, typing.Any]:
    try:
        import yaml

        value = yaml.safe_load(path.read_text())
    except ModuleNotFoundError as error:
        raise IntegrationError("PyYAML is required for game repository discovery") from error
    except (OSError, ValueError) as error:
        raise IntegrationError(f"read {path}: {error}") from error
    except Exception as error:
        raise IntegrationError(f"decode {path}: {error}") from error
    if not isinstance(value, dict):
        raise IntegrationError(f"{path} must contain a YAML object")
    return value


def _duration(value: typing.Any) -> float:
    if not isinstance(value, str):
        raise IntegrationError("checker_timeout must be a duration string")
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(ms|s|m)", value.strip())
    if match is None:
        raise IntegrationError(f"unsupported checker_timeout {value!r}")
    amount = float(match.group(1))
    return amount * {"ms": 0.001, "s": 1.0, "m": 60.0}[match.group(2)]


def _compose_configuration(compose: pathlib.Path) -> dict[str, typing.Any]:
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", str(compose), "config", "--format", "json"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError as error:
        raise IntegrationError("docker compose is required") from error
    if result.returncode != 0:
        raise IntegrationError(f"docker compose config failed:\n{result.stderr.strip()}")
    try:
        value = json.loads(result.stdout)
    except ValueError as error:
        raise IntegrationError("docker compose returned invalid configuration") from error
    if not isinstance(value, dict) or not isinstance(value.get("services"), dict):
        raise IntegrationError("docker compose configuration has no services")
    return value


def _gateway_service(
    services: dict[str, typing.Any], ports: tuple[int, ...]
) -> tuple[str, tuple[str, ...]]:
    candidates: set[str] | None = None
    published: set[str] = set()
    for port in ports:
        matches = {
            name
            for name, definition in services.items()
            if isinstance(definition, dict)
            and any(
                isinstance(binding, dict)
                and binding.get("protocol", "tcp") == "tcp"
                and binding.get("target") == port
                for binding in definition.get("ports", [])
            )
        }
        if not matches:
            raise IntegrationError(
                f"manifest port {port} is not published by the service Compose file"
            )
        published.update(matches)
        candidates = matches if candidates is None else candidates & matches
    if candidates is None or len(candidates) != 1:
        raise IntegrationError(
            "all manifest ports must be published by one Compose gateway service"
        )
    return next(iter(candidates)), tuple(sorted(published))


def load_project(service: str, start: pathlib.Path | None = None) -> ProjectConfig:
    root = _find_root((start or pathlib.Path.cwd()).resolve())
    game = _yaml_object(root / "game.yaml")
    if service not in game.get("services", []):
        raise IntegrationError(f"service {service!r} is not enabled in game.yaml")
    manifest_path = root / "services" / service / "manifest.yaml"
    checker_compose = root / "checkers" / service / "compose.yaml"
    if not manifest_path.is_file() or not checker_compose.is_file():
        raise IntegrationError(f"service {service!r} is missing its manifest or checker")
    manifest = _yaml_object(manifest_path)
    stores = manifest.get("stores")
    ports = manifest.get("ports")
    if manifest.get("id") != service:
        raise IntegrationError(f"manifest id must be {service!r}")
    if not isinstance(stores, list) or not stores or not all(isinstance(v, str) for v in stores):
        raise IntegrationError("manifest stores must be a non-empty string list")
    if not isinstance(ports, list) or not ports or not all(isinstance(v, int) for v in ports):
        raise IntegrationError("manifest ports must be a non-empty integer list")
    flag_prefix = game.get("flag_prefix")
    if not isinstance(flag_prefix, str) or not flag_prefix:
        raise IntegrationError("game flag_prefix must be a non-empty string")
    compose = _compose_configuration(root / "services" / service / "compose.yaml")
    gateway, published = _gateway_service(compose["services"], tuple(ports))
    return ProjectConfig(
        root=root,
        service=service,
        stores=tuple(stores),
        flag_prefix=flag_prefix,
        timeout=_duration(manifest.get("checker_timeout")),
        gateway=gateway,
        service_names=tuple(compose["services"]),
        published_services=published,
    )


def _checker_from_module(module_name: str = "main") -> Checker:
    module = importlib.import_module(module_name)
    configured = getattr(module, "checker", None)
    if configured is not None:
        return typing.cast(Checker, configured)
    candidates = [
        value
        for value in vars(module).values()
        if inspect.isclass(value)
        and value.__module__ == module.__name__
        and all(
            inspect.iscoroutinefunction(getattr(value, name, None))
            for name in ("put", "get", "check")
        )
    ]
    if len(candidates) != 1:
        raise IntegrationError(
            "checker main.py must expose `checker` or define exactly one checker class"
        )
    return typing.cast(Checker, candidates[0]())


def _inside() -> int:
    try:
        value = json.loads(os.environ["VAD_INTEGRATION_CONFIG"])
        config = IntegrationConfig(
            service=value["service"],
            stores=tuple(value["stores"]),
            host=value["host"],
            flag_prefix=value["flag_prefix"],
            timeout=float(value["timeout"]),
            startup_timeout=float(value["startup_timeout"]),
        )
        asyncio.run(run_integration(_checker_from_module(), config))
    except (ImportError, KeyError, TypeError, ValueError, IntegrationError) as error:
        print(f"integration failed: {error}", file=sys.stderr)
        return 1
    return 0


def _run(
    command: list[str], *, check: bool = True, quiet: bool = False
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.setdefault("COMPOSE_PROGRESS", "quiet")
    try:
        result = subprocess.run(
            command,
            text=True,
            check=False,
            env=environment,
            stdout=subprocess.PIPE if quiet else None,
            stderr=subprocess.STDOUT if quiet else None,
        )
    except FileNotFoundError as error:
        raise IntegrationError("docker compose is required") from error
    if check and result.returncode != 0:
        if quiet and result.stdout:
            print(result.stdout.rstrip(), file=sys.stderr)
        raise IntegrationError(f"command failed with exit code {result.returncode}")
    return result


def _redact_logs(value: str) -> str:
    return re.sub(r"([?&]token=)[^&\s\"]+", r"\1<redacted>", value)


def run_project(project: ProjectConfig) -> None:
    project_name = f"vad-integration-{project.service}-{secrets.token_hex(4)}"
    package_directory = pathlib.Path(__file__).resolve().parent
    override = "services:\n" + "".join(
        f"  {name}:\n    ports: !reset []\n" for name in project.published_services
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml") as overlay:
        overlay.write(override)
        overlay.flush()
        compose = [
            "docker",
            "compose",
            "--project-name",
            project_name,
            "-f",
            str(project.service_compose),
            "-f",
            str(project.checker_compose),
            "-f",
            overlay.name,
        ]
        try:
            print(f"Starting {project.service} service...", flush=True)
            _run(
                [*compose, "up", "--build", "--detach", *project.service_names],
                quiet=True,
            )
            _run([*compose, "build", "checker"], quiet=True)
            config = json.dumps(
                {
                    "service": project.service,
                    "stores": project.stores,
                    "host": project.gateway,
                    "flag_prefix": project.flag_prefix,
                    "timeout": project.timeout,
                    "startup_timeout": 60.0,
                },
                separators=(",", ":"),
            )
            print("Running checker integration...", flush=True)
            result = _run(
                [
                    *compose,
                    "run",
                    "--rm",
                    "-e",
                    f"VAD_INTEGRATION_CONFIG={config}",
                    "-e",
                    "PYTHONPATH=/vad-sdk",
                    "-e",
                    "PYTHONUNBUFFERED=1",
                    "-v",
                    f"{package_directory}:/vad-sdk/vad_checker:ro",
                    "checker",
                    "python",
                    "-m",
                    "vad_checker.integration",
                ],
                check=False,
                quiet=True,
            )
            if result.stdout:
                print(result.stdout.rstrip(), flush=True)
            if result.returncode != 0:
                if result.stdout and any(
                    outcome in result.stdout
                    for outcome in ("SERVICE_FAILURE", "CHECKER_FAILURE")
                ):
                    logs = _run(
                        [*compose, "logs", "--no-color", "--tail", "20"],
                        check=False,
                        quiet=True,
                    )
                    if logs.stdout:
                        print(_redact_logs(logs.stdout.rstrip()))
                raise _ReportedIntegrationError
            print(f"{project.service}: integration ok", flush=True)
        finally:
            _run(
                [
                    *compose,
                    "down",
                    "--timeout",
                    "2",
                    "--volumes",
                    "--rmi",
                    "local",
                    "--remove-orphans",
                ],
                check=False,
                quiet=True,
            )


def main(argv: list[str] | None = None) -> int:
    if "VAD_INTEGRATION_CONFIG" in os.environ:
        return _inside()
    parser = argparse.ArgumentParser(description="Test a VAD service and checker")
    parser.add_argument("service", help="service ID from game.yaml")
    arguments = parser.parse_args(argv)
    try:
        run_project(load_project(arguments.service))
    except _ReportedIntegrationError:
        return 1
    except IntegrationError as error:
        print(f"integration failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
