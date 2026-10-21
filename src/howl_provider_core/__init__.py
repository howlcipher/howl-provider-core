"""Small, provider-neutral execution boundary. No discovery or service launching."""

from .redaction import REDACTED, SECRET_PATTERNS, redact, scrub, secret_env_values
from .runtime import (
    BudgetExceeded,
    CallBudget,
    CommandConfig,
    CommandProvider,
    Execution,
    Policy,
    ProviderError,
    classify_failure,
    guarded_opener,
    reported_metadata,
)

__all__ = [
    "REDACTED",
    "SECRET_PATTERNS",
    "BudgetExceeded",
    "CallBudget",
    "CommandConfig",
    "CommandProvider",
    "Execution",
    "Policy",
    "ProviderError",
    "classify_failure",
    "guarded_opener",
    "redact",
    "reported_metadata",
    "scrub",
    "secret_env_values",
]
