# Change log

## Unreleased

Honor the ecosystem's `FORBID_LOCAL_INFERENCE` environment variable alongside
`HOWL_FORBID_LOCAL_INFERENCE`. Either prohibition overrides explicit local opt-in;
an invalid generic value fails closed. Regression tests exercise both aliases
without dispatching inference.

## 0.2.1

Mission 007 F2: restore optional bearer prefixes for all credential assignments
and hyphenated GitHub tokens. Add historical Writer Google, Slack, JWT and
standalone bearer patterns. Scrub decoded command output and reported metadata
before consumer persistence, including failure telemetry. Synthetic regressions
cover all adapters, downstream receipts, logs and errors.


0.2.0: one set of secret-redaction rules for every component that persists text
(issue #4). `redact(text, secrets=())`, `scrub(value, secrets=())` and
`secret_env_values(environ)` are public; the patterns are the union of the
copies in howldream, howlcreate and howlproof (adding AWS access keys and
`github_pat_` tokens where they were missing). `CommandProvider` uses the same
environment-secret rule it used inline before.

Command semantic tests now allow two seconds of startup headroom. Separate timeout
and cancellation tests prove child readiness and process cleanup; malformed JSON
responses have explicit coverage. Production limits and policy are unchanged.

## 0.1.0

Added explicit local opt-in with an overriding prohibition, guarded HTTP transport,
operator-controlled bounded command execution, truthful execution metadata, and
finite attempt accounting. No provider service discovery or local model execution.

## Resilience hardening (2026-10-02)

- Categorized command failures using allowlisted static messages and recovery policies.
- Preserved known usage/cost/model/request telemetry when adapter parsing fails.
- Added raw-output/parse-state metadata and stricter numeric/identity filtering.
- Retained restrictive local policy, bounded processes, no automatic transport retries.

- Invalid nested OpenAI/Gemini completion shapes retain failure telemetry instead of leaking parser exceptions.
