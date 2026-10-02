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
Semantic command tests allow two seconds for process startup. Focused timeout and
cancellation tests require child readiness markers and check process cleanup.

## Structured adapters and failures

`adapter` (or `output_format`) accepts `text`/`raw-text`, `json`/`generic-json`,
`claude-json`, `openai-json`, and `gemini-json`. Use the CLI's matching JSON output
flag. `openai-json` decodes a single OpenAI completion object or `{text: ...}`;
it does not decode Codex JSONL event streams. `claude-json` reads `modelUsage`,
`usage`, `total_cost_usd`, and session identity. Configured model labels are
requested identity; missing observed model remains unknown. Generic JSON can
supply `cost` and `request_id`; no pricing estimate is made.

`ProviderError.failure` is a static-message envelope with `category`, `recovery`,
`retryable`, and `exit_code`. Categories: RATE_LIMIT, SESSION_LIMIT,
AUTHENTICATION, PROVIDER_UNAVAILABLE, CONTEXT_LIMIT, MALFORMED_RESPONSE, TIMEOUT,
CANCELLED, PROCESS_FAILURE, BUDGET_EXHAUSTED. Recovery is RETRYABLE,
NON_RETRYABLE, HUMAN_ACTION, or REPAIRABLE. Classification uses bounded provider
text in memory, then discards that text. Unknown failures stay PROCESS_FAILURE;
no provider body is copied into the message. `ProviderError.execution` retains
known numeric usage/cost, model, request identity, elapsed time, and parse state,
including when decoding fails. Missing telemetry remains null. Positive reported
usage establishes inference occurred; absent usage does not prove no inference.

The transport performs no automatic retries. Callers must use a shared budget
for repairs or authorized fallback. Authentication, session limits, cancellation,
and exhausted budgets require an explicit next action. Command providers do not
apply sampling parameters; a profile model label is not evidence of model selection.
Timeout remains 120 seconds, configurable per reviewed profile up to 600 seconds;
use 300 seconds for a slow remote CLI only when appropriate to that provider.

Invalid nested completion shapes are reported as malformed responses while retaining known usage.
