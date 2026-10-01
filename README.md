# Howl Provider Core

A small Python 3.11+ library for restrictive inference policy, bounded HTTP and
command transport, execution metadata, and invocation budgets. No discovery,
model weights, services, SDKs, tools, or framework dependencies.

`Policy()` forbids local inference by default. Explicit `Policy(allow_local=True)`
is overridden by `HOWL_FORBID_LOCAL_INFERENCE=1` or `forbid_local=True`. Both
adapter selection and dispatch must check policy. `guarded_opener(policy)` disables
proxies and redirects, validates DNS destinations, and connects to validated
literal addresses while retaining hostname TLS authentication. Non-public IPs
are conservatively classified as local; remote LAN inference needs local opt-in.

Command providers execute **trusted operator programs**, not model-supplied code.
Never discover command profiles in source repositories or generated artifacts.
The caller must explicitly supply and review the profile. `shell=False` prevents
shell interpolation but cannot prove that an arbitrary program is remote or safe.
Known local launchers and shells are rejected; wrappers remain an operator trust
boundary. Audit tools, hooks, endpoint overrides, local fallback, and authentication
for the particular CLI. The remote flag is labeled `OPERATOR_DECLARED`.

```json
{
  "argv": ["YOUR_REVIEWED_REMOTE_CLI", "YOUR_DATA_ONLY_ARGUMENT"],
  "remote": true,
  "timeout_seconds": 120,
  "max_output_bytes": 2097152,
  "env_allowlist": [],
  "output_format": "text"
}
```

Prompts use stdin. Execution uses a private temporary cwd and a minimal environment
(PATH, HOME, LANG, SSL certificate paths, explicitly allowed authentication variables).
The restrictive policy reaches child Howl components. stdout/stderr are independently
bounded; stderr bodies and environment values are never logged. Credential values
in explicitly passed KEY/TOKEN/SECRET/PASSWORD variables are redacted from stdout.
This is best-effort redaction, not a guarantee against encoded secret disclosure.
Timeout/cancellation kills and reaps the process group, including descendants.
Command transport currently requires POSIX; HTTP and policy are portable.

Text mode cannot establish actual model, token usage, or inference occurrence.
Those fields remain null. Optional JSON mode accepts a provider-neutral response:
`{"text":"...","model":"reported-model","provider":"reported-service","usage":null}`.
Optional boolean deterministic/mocked/inference_occurred values are descriptive
provider reports. Configured `model` is recorded separately as requested_model.
No costs are estimated. `CallBudget` counts attempts immediately before dispatch;
missing usage is never replaced with zero.

## Verification

```bash
pip install -e '.[dev]'
ruff check src tests
ruff format --check src tests
flake8 src tests --max-line-length=100 --extend-ignore=E203,W503
pytest -q
python -m build
```

Tests use fake commands and mock sockets. They do not require any model service.
