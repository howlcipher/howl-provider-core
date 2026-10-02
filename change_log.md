# Change log

## Unreleased

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
