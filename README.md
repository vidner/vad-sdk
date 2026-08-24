# vad checker SDK

Challenge checkers implement three asynchronous methods: `put`, `get`, and `check`. The runner provides a validated per-job `Context`, enforces the platform deadline and bounded concurrency, publishes a result durably, and acknowledges the JetStream job only after the result publish succeeds.

Install for development:

```bash
python -m pip install -e .
```

`PUT` returns `State(public={...}, private={...})`. `GET` receives exactly that flag's `context.flag`, `context.store`, `context.public`, and `context.private`. Checker exceptions default to `CHECKER_FAILURE`; a service-specific exception may expose an `outcome` and a short `detail_code` attribute.

Exceeding the platform job deadline produces `SERVICE_FAILURE` with the detail
code `service_timeout`, because a target can deliberately keep a checker request
open. Unexpected checker exceptions continue to produce `CHECKER_FAILURE`.

## Service integration tests

The SDK owns the common checker integration contract. Repository discovery,
Compose orchestration, and the checker contract are available from a game
repository containing `game.yaml`, `services/`, and `checkers/`:

```bash
python -m vad_checker.integration notes
```

The service must already be running (`docker compose up --build -d` from the
service's Compose file); the command refuses to start otherwise. It builds the
checker image, attaches it to the running service, runs the integration
contract, and prints service logs on failure. It leaves the service running
afterward, so it calls the same library API directly:

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
