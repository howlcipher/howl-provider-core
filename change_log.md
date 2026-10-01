# Change log

## Unreleased

Command semantic tests now allow two seconds of startup headroom. Separate timeout
and cancellation tests prove child readiness and process cleanup; malformed JSON
responses have explicit coverage. Production limits and policy are unchanged.

## 0.1.0

Added explicit local opt-in with an overriding prohibition, guarded HTTP transport,
operator-controlled bounded command execution, truthful execution metadata, and
finite attempt accounting. No provider service discovery or local model execution.
