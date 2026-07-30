# vad checker SDK

Challenge checkers implement three asynchronous methods: `put`, `get`, and `check`. The runner provides a validated per-job `Context`, enforces the platform deadline and bounded concurrency, publishes a result durably, and acknowledges the JetStream job only after the result publish succeeds.

Install for development:

```bash
python -m pip install -e ./sdk/python
```

`PUT` returns `State(public={...}, private={...})`. `GET` receives exactly that flag's `context.flag`, `context.store`, `context.public`, and `context.private`. Checker exceptions default to `CHECKER_FAILURE`; a service-specific exception may expose an `outcome` and a short `detail_code` attribute.
