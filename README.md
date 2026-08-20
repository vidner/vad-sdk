# vad checker SDK

Challenge checkers implement three asynchronous methods: `put`, `get`, and `check`. The runner provides a validated per-job `Context`, enforces the platform deadline and bounded concurrency, publishes a result durably, and acknowledges the JetStream job only after the result publish succeeds.

Install for development:

```bash
python -m pip install -e .
```

`PUT` returns `State(public={...}, private={...})`. `GET` receives exactly that flag's `context.flag`, `context.store`, `context.public`, and `context.private`. Checker exceptions default to `CHECKER_FAILURE`; a service-specific exception may expose an `outcome` and a short `detail_code` attribute.

## Service integration tests

The SDK owns the common checker integration contract. Repository discovery,
Compose orchestration, and the checker contract are available from a game
repository containing `game.yaml`, `services/`, and `checkers/`:

```bash
python -m vad_checker.integration notes
```

The command builds an isolated Compose project, runs the integration contract
inside the checker image, prints service logs on failure, and removes its
containers and volumes afterward. It calls the same library API directly:

```python
import asyncio

from main import NotesChecker
from vad_checker.integration import IntegrationConfig, run_integration


def validate_state(store, state):
    if store == "private_notes":
        assert set(state.public) == {"note_id"}


asyncio.run(run_integration(
    NotesChecker(),
    IntegrationConfig(
        service="notes",
        stores=("private_notes", "shared_drafts"),
        host="host.docker.internal",
        flag_prefix="CTF",
    ),
    validate_state=validate_state,
))
```

Keep service-specific unit and regression tests separate from this generic
contract.
