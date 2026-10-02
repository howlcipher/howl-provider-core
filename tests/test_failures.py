"""Sanitized provider failures preserve telemetry without stderr bodies."""

import json
import sys
import threading

import pytest

from howl_provider_core import CommandConfig, CommandProvider, ProviderError


def command(code, **kwargs):
    return CommandProvider(CommandConfig((sys.executable, "-c", code), True, **kwargs))


@pytest.mark.parametrize(
    "message,category,recovery",
    [
        ("session limit reached password=secret", "SESSION_LIMIT", "HUMAN_ACTION"),
        ("rate limit 429 token=secret", "RATE_LIMIT", "RETRYABLE"),
        ("invalid API key secret", "AUTHENTICATION", "NON_RETRYABLE"),
        ("context length exceeded secret", "CONTEXT_LIMIT", "NON_RETRYABLE"),
        ("provider overloaded secret", "PROVIDER_UNAVAILABLE", "RETRYABLE"),
        ("unexpected secret", "PROCESS_FAILURE", "NON_RETRYABLE"),
    ],
)
def test_command_failure_category(message, category, recovery):
    with pytest.raises(ProviderError) as caught:
        command(f"import sys; print({message!r}); sys.exit(1)").generate("fixture")
    error = caught.value
    assert error.failure["category"] == category
    assert error.failure["recovery"] == recovery
    assert error.failure["exit_code"] == 1
    assert "secret" not in json.dumps(error.failure)
    assert "secret" not in str(error)
    assert error.execution["raw_output_received"] is True
    assert error.execution["inference_occurred"] is None


def test_adapter_parse_failure_preserves_usage():
    payload = {
        "model": "fixture",
        "usage": {"input_tokens": 7},
        "total_cost_usd": 0.03,
        "session_id": "request-1",
        "result": None,
    }
    with pytest.raises(ProviderError) as caught:
        command(
            "import json; print(json.dumps(" + repr(payload) + "))", adapter="claude-json"
        ).generate("fixture")
    error = caught.value
    assert error.failure["category"] == "MALFORMED_RESPONSE"
    assert error.execution["usage"] == {"input_tokens": 7}
    assert error.execution["cost"] == 0.03
    assert error.execution["request_id"] == "request-1"
    assert error.execution["model"] == "fixture"


def test_structured_error_never_interpolates_provider_body():
    payload = {"is_error": True, "error": "rate limit api_key=secret-value"}
    with pytest.raises(ProviderError) as caught:
        command(
            "import json; print(json.dumps(" + repr(payload) + "))", adapter="claude-json"
        ).generate("fixture")
    assert caught.value.failure["category"] == "RATE_LIMIT"
    assert "secret-value" not in str(caught.value)


@pytest.mark.parametrize("cancel", [False, True])
def test_timeout_and_cancel_envelopes(cancel):
    event = threading.Event()
    if cancel:
        event.set()
    with pytest.raises(ProviderError) as caught:
        command("import time; time.sleep(3)", timeout_seconds=0.1).generate("fixture", event)
    assert caught.value.failure["category"] == ("CANCELLED" if cancel else "TIMEOUT")
    assert caught.value.execution["elapsed_seconds"] >= 0
