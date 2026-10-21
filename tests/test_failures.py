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


@pytest.mark.parametrize(
    "adapter,payload",
    [
        ("openai-json", {"choices": [None], "model": "fixture", "usage": {"prompt_tokens": 12}}),
        (
            "gemini-json",
            {
                "candidates": [{"content": None}],
                "modelVersion": "fixture",
                "usageMetadata": {"promptTokenCount": 12},
            },
        ),
    ],
)
def test_invalid_nested_adapter_shape_preserves_usage(adapter, payload):
    with pytest.raises(ProviderError) as caught:
        command("import json; print(json.dumps(" + repr(payload) + "))", adapter=adapter).generate(
            "fixture"
        )
    assert caught.value.failure["category"] == "MALFORMED_RESPONSE"
    assert caught.value.execution["model"] == "fixture"
    assert 12 in caught.value.execution["usage"].values()
    assert caught.value.execution["parse_status"] == "FAILED"


@pytest.mark.parametrize("adapter", ["text", "json", "claude-json", "openai-json", "gemini-json"])
def test_unknown_credentials_do_not_escape_command_results(adapter, caplog, capsys):
    echo = "token: bearer syntheticPrivate456 ghp_abcdefghijkl-mnopqrstuvwxyz"
    payload = {
        "text": echo,
        "result": echo,
        "model": "token: bearer syntheticMetadata456",
        "candidates": [{"content": {"parts": [{"text": echo}]}}],
        "choices": [{"message": {"content": echo}}],
    }
    raw = echo if adapter == "text" else json.dumps(payload)
    output, execution = command("print(" + repr(raw) + ")", adapter=adapter).generate("fixture")
    combined = output + json.dumps(execution.to_dict()) + caplog.text + str(capsys.readouterr())
    for secret in ("syntheticPrivate456", "abcdefghijkl-mnopqrstuvwxyz", "syntheticMetadata456"):
        assert secret not in combined


def test_unknown_credentials_do_not_escape_command_failures(caplog, capsys):
    echo = "token: bearer syntheticPrivate456 ghp_abcdefghijkl-mnopqrstuvwxyz"
    with pytest.raises(ProviderError) as caught:
        command(f"import sys; print({echo!r}, file=sys.stderr); sys.exit(1)").generate("fixture")
    error = caught.value
    combined = str(error) + json.dumps(error.failure) + json.dumps(error.execution)
    combined += caplog.text + str(capsys.readouterr())
    assert "syntheticPrivate456" not in combined
    assert "abcdefghijkl-mnopqrstuvwxyz" not in combined


def test_redacting_structured_completion_preserves_json_contract():
    payload = {"token": "bearer syntheticPrivate456", "ordinary": "preserved"}
    output, _ = command("print(" + repr(json.dumps(payload)) + ")").generate("fixture")
    assert json.loads(output) == {"token": "[REDACTED]", "ordinary": "preserved"}


def test_ordinary_completion_bytes_are_preserved():
    payload = '{"ordinary": [1, 2], "text": "preserved"}'
    output, _ = command("print(" + repr(payload) + ")").generate("fixture")
    assert output == payload + "\n"
