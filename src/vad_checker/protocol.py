from __future__ import annotations

import dataclasses
import datetime
import enum
import json
from typing import Any

VERSION = 1
MAX_MESSAGE_BYTES = 32 * 1024
MAX_STATE_BYTES = 8 * 1024


class Outcome(str, enum.Enum):
    SUCCESS = "SUCCESS"
    SERVICE_FAILURE = "SERVICE_FAILURE"
    FLAG_MISSING = "FLAG_MISSING"
    CHECKER_FAILURE = "CHECKER_FAILURE"


@dataclasses.dataclass(frozen=True)
class State:
    public: dict[str, Any]
    private: dict[str, Any]


@dataclasses.dataclass(frozen=True)
class Context:
    job_id: str
    attempt: int
    operation: str
    deadline: datetime.datetime
    game_id: int
    tick: int
    service: str
    team: str
    host: str
    store: str | None
    flag: str | None
    public: dict[str, Any] | None
    private: dict[str, Any] | None

    @property
    def idempotency_key(self) -> str:
        return self.job_id


@dataclasses.dataclass(frozen=True)
class Result:
    outcome: Outcome
    detail_code: str = ""
    state: State | None = None


def decode_job(data: bytes) -> Context:
    if not data or len(data) > MAX_MESSAGE_BYTES:
        raise ValueError("checker job size is invalid")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("checker job must be an object")
    required = {"version", "id", "attempt", "operation", "deadline", "game", "service", "team"}
    optional = {"store", "flag", "public", "private"}
    if set(value) - required - optional or not required <= set(value):
        raise ValueError("checker job fields are invalid")
    if value["version"] != VERSION or not isinstance(value["id"], str) or not value["id"]:
        raise ValueError("checker job envelope is invalid")
    if not isinstance(value["attempt"], int) or isinstance(value["attempt"], bool) or value["attempt"] <= 0:
        raise ValueError("checker job attempt is invalid")
    operation = value["operation"]
    if operation not in {"PUT", "GET", "CHECK"}:
        raise ValueError("checker operation is invalid")
    deadline = _datetime(value["deadline"])
    game = _object(value["game"], {"id", "tick"})
    service = _object(value["service"], {"id", "key"})
    team = _object(value["team"], {"id", "name", "host"})
    store_value = value.get("store")
    store = _object(store_value, {"id", "key"}) if store_value is not None else None
    public = _state_object(value.get("public"), "public")
    private = _state_object(value.get("private"), "private")
    flag = value.get("flag")
    if flag is not None and (not isinstance(flag, str) or not flag):
        raise ValueError("checker flag is invalid")
    if operation == "PUT" and (store is None or flag is None or public is not None or private is not None):
        raise ValueError("PUT checker fields are invalid")
    if operation == "GET" and (store is None or flag is None or public is None or private is None):
        raise ValueError("GET checker fields are invalid")
    if operation == "CHECK" and (store is not None or flag is not None or public is not None or private is not None):
        raise ValueError("CHECK checker fields are invalid")
    return Context(
        job_id=value["id"],
        attempt=value["attempt"],
        operation=operation,
        deadline=deadline,
        game_id=_positive_int(game["id"]),
        tick=_positive_int(game["tick"]),
        service=_nonempty_string(service["key"]),
        team=_nonempty_string(team["name"]),
        host=_nonempty_string(team["host"]),
        store=_nonempty_string(store["key"]) if store else None,
        flag=flag,
        public=public,
        private=private,
    )


def encode_result(context: Context, result: Result, started: datetime.datetime, completed: datetime.datetime) -> bytes:
    if completed < started:
        raise ValueError("result completion precedes its start")
    payload: dict[str, Any] = {
        "version": VERSION,
        "job_id": context.job_id,
        "attempt": context.attempt,
        "outcome": result.outcome.value,
        "started_at": _format_datetime(started),
        "completed_at": _format_datetime(completed),
    }
    if result.detail_code:
        payload["detail_code"] = result.detail_code[:128]
    if result.outcome is Outcome.SUCCESS and context.operation == "PUT":
        if result.state is None:
            raise ValueError("successful PUT must return state")
        _validate_state_size(result.state.public, "public")
        _validate_state_size(result.state.private, "private")
        payload["public"] = result.state.public
        payload["private"] = result.state.private
    elif result.state is not None:
        raise ValueError("only successful PUT may return state")
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise ValueError("checker result is too large")
    return encoded


def _object(value: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("checker nested object is invalid")
    return value


def _state_object(value: Any, name: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError(f"{name} state must be an object")
    _validate_state_size(value, name)
    return value


def _validate_state_size(value: dict[str, Any], name: str) -> None:
    encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    if len(encoded) > MAX_STATE_BYTES:
        raise ValueError(f"{name} state is too large")


def _positive_int(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError("checker identifier is invalid")
    return value


def _nonempty_string(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("checker string is invalid")
    return value


def _datetime(value: Any) -> datetime.datetime:
    if not isinstance(value, str):
        raise ValueError("checker deadline is invalid")
    parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("checker deadline requires a timezone")
    return parsed.astimezone(datetime.UTC)


def _format_datetime(value: datetime.datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("result timestamp requires a timezone")
    return value.astimezone(datetime.UTC).isoformat().replace("+00:00", "Z")
