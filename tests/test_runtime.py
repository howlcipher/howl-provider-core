import socket
import subprocess
import sys
import threading
import time
from unittest.mock import patch

import pytest

from howl_provider_core import (
    BudgetExceeded,
    CallBudget,
    CommandConfig,
    CommandProvider,
    Policy,
    ProviderError,
)


def test_prohibition_overrides_permission(monkeypatch):
    monkeypatch.setenv("HOWL_FORBID_LOCAL_INFERENCE", "1")
    policy = Policy(allow_local=True)
    with pytest.raises(ProviderError):
        policy.check_provider("ollama")
    for url in [
        "http://localhost:11434",
        "https://127.1",
        "https://[::1]",
        "https://127.0.0.2",
        "https://[::ffff:127.0.0.1]",
        "https://192.168.1.1",
    ]:
        with pytest.raises(ProviderError):
            policy.check_url(url)


def test_dns_blocked_before_connection():
    addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
    with (
        patch("socket.getaddrinfo", return_value=addresses),
        patch("socket.create_connection") as call,
    ):
        with pytest.raises(ProviderError):
            Policy().connect(("remote.example", 443))
        call.assert_not_called()


def test_dns_destination_pinned():
    addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
    with (
        patch("socket.getaddrinfo", return_value=addresses),
        patch("socket.create_connection") as call,
    ):
        Policy().connect(("remote.example", 443))
        assert call.call_args.args[0] == ("8.8.8.8", 443)


def test_call_budget():
    budget = CallBudget(1)
    budget.consume("fake")
    with pytest.raises(BudgetExceeded):
        budget.consume("fake")
    assert budget.calls == 1


def command(code, **kwargs):
    return CommandProvider(CommandConfig((sys.executable, "-c", code), True, **kwargs))


@pytest.fixture
def launched_processes(monkeypatch):
    processes = []
    launch = subprocess.Popen

    def capture(*args, **kwargs):
        process = launch(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", capture)
    return processes


def test_literal_stdin_and_environment(monkeypatch):
    monkeypatch.setenv("SECRET_UNRELATED", "secret-value")
    provider = command(
        'import sys,os; print(sys.stdin.read()); print(os.getenv("SECRET_UNRELATED"))'
    )
    text, metadata = provider.generate("$(touch malicious); `uname`")
    assert "$(touch malicious)" in text and "None" in text
    assert metadata.remote_observation == "OPERATOR_DECLARED"
    assert metadata.inference_occurred is None


@pytest.mark.parametrize(
    "code,message",
    [
        ('import sys; print("secret",file=sys.stderr); sys.exit(4)', "exit code 4"),
        ('print("x"*1000)', "output limit"),
        ("pass", "empty output"),
    ],
)
def test_failures_sanitized(code, message):
    # Semantic failures must allow ordinary interpreter startup on slower hosts.
    provider = command(code, timeout_seconds=2, max_output_bytes=100)
    with pytest.raises(ProviderError, match=message) as error:
        provider.generate("test")
    assert "secret" not in str(error.value)


def test_timeout_after_child_started(tmp_path, launched_processes):
    marker = tmp_path / "started"
    code = f"import pathlib,time; pathlib.Path({str(marker)!r}).touch(); time.sleep(30)"
    started = time.monotonic()
    with pytest.raises(ProviderError, match="timed out"):
        command(code, timeout_seconds=2).generate("test")
    assert marker.exists(), "child must start before timeout enforcement is credited"
    assert 2 <= time.monotonic() - started < 6
    assert len(launched_processes) == 1
    assert launched_processes[0].returncode is not None


@pytest.mark.parametrize("payload", ["{", "{}", '{"text":"answer","usage":42}'])
def test_malformed_command_json(payload):
    with pytest.raises(ProviderError, match="malformed command JSON response"):
        command("print(" + repr(payload) + ")", output_format="json", timeout_seconds=2).generate(
            "test"
        )


def test_cancellation():
    cancellation = threading.Event()
    cancellation.set()
    with pytest.raises(ProviderError, match="cancelled"):
        command("import time; time.sleep(2)").generate("test", cancellation)


@pytest.mark.parametrize(
    "argv", [("bash", "-c", "anything"), ("ollama", "run", "x"), ("codex", "--oss")]
)
def test_launchers_rejected(argv):
    with pytest.raises(ProviderError):
        CommandConfig(argv, True)


def test_secret_echo_redacted(monkeypatch):
    monkeypatch.setenv("EXPLICIT_API_KEY", "super-sensitive-key")
    output, _ = command(
        'import os; print(os.getenv("EXPLICIT_API_KEY"))', env_allowlist=("EXPLICIT_API_KEY",)
    ).generate("test")
    assert "super-sensitive-key" not in output
    assert "[REDACTED]" in output


def test_reported_model_distinct_from_requested():
    import json

    payload = json.dumps(
        {
            "text": "answer",
            "model": "actual-model",
            "provider": "fake-service",
            "inference_occurred": True,
            "usage": {"output_tokens": 2},
        }
    )
    output, metadata = command(
        "print(" + repr(payload) + ")", output_format="json", model="requested-model"
    ).generate("test")
    assert output == "answer"
    assert metadata.model == "actual-model"
    assert metadata.requested_model == "requested-model"
    assert metadata.actual_provider == "fake-service"
    _, text_metadata = command('print("answer")', model="requested").generate("test")
    assert text_metadata.model is None
    assert text_metadata.inference_occurred is None


def test_descendant_terminated(tmp_path, launched_processes):
    import os
    import pathlib

    pid_file = tmp_path / "child.pid"
    code = (
        "import subprocess,sys,time; "
        'child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"]); '
        f'open({str(pid_file)!r},"w").write(str(child.pid)); time.sleep(30)'
    )
    with pytest.raises(ProviderError, match="timed out"):
        command(code, timeout_seconds=2).generate("test")
    assert pid_file.exists(), "descendant must be launched before checking cleanup"
    assert len(launched_processes) == 1
    assert launched_processes[0].returncode is not None
    pid = int(pid_file.read_text())
    for _ in range(20):
        status = pathlib.Path(f"/proc/{pid}/stat")
        if not status.exists() or status.read_text().split()[2] == "Z":
            break
        time.sleep(0.02)
    else:
        os.kill(pid, 9)
        pytest.fail("descendant was still running after timeout")


def test_cancellation_after_child_closes_pipes(tmp_path, launched_processes):
    cancellation = threading.Event()
    marker = tmp_path / "pipes_closed"

    def cancel_when_ready():
        deadline = time.monotonic() + 5
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        cancellation.set()

    watcher = threading.Thread(target=cancel_when_ready)
    watcher.start()
    try:
        with pytest.raises(ProviderError, match="cancelled"):
            command(
                "import os,pathlib,time; os.close(0); os.close(1); os.close(2); "
                f"pathlib.Path({str(marker)!r}).touch(); time.sleep(30)",
                timeout_seconds=10,
            ).generate("test", cancellation)
        assert marker.exists(), "cancellation must happen after the child closes its pipes"
        assert len(launched_processes) == 1
        assert launched_processes[0].returncode is not None
    finally:
        watcher.join(timeout=6)
        assert not watcher.is_alive()


def test_claude_json_adapter():
    claude_payload = {
        "result": "Defensive design proposal",
        "modelUsage": {
            "claude-sonnet-5-5": {
                "inputTokens": 100,
                "outputTokens": 50,
                "costUSD": 0.005,
            }
        },
        "usage": {"input_tokens": 100, "output_tokens": 50},
        "total_cost_usd": 0.005,
        "session_id": "sess-abc-123",
        "type": "result",
    }
    output, meta = command(
        "import json; print(json.dumps(" + repr(claude_payload) + "))",
        adapter="claude-json",
        model="claude-sonnet-5-5",
    ).generate("test prompt")
    assert output == "Defensive design proposal"
    assert meta.model == "claude-sonnet-5-5"
    assert meta.actual_provider == "claude"
    assert meta.adapter == "claude-json"
    assert meta.usage == {"input_tokens": 100, "output_tokens": 50}
    assert meta.cost == 0.005
    assert meta.request_id == "sess-abc-123"
    assert meta.inference_occurred is True


def test_claude_json_adapter_error():
    error_payload = {
        "is_error": True,
        "subtype": "error",
        "error": "rate limit exceeded",
    }
    with pytest.raises(ProviderError, match="Claude CLI error"):
        command(
            "import json; print(json.dumps(" + repr(error_payload) + "))",
            adapter="claude-json",
        ).generate("test")


def test_openai_json_adapter():
    openai_payload = {
        "id": "chatcmpl-999",
        "model": "gpt-4o",
        "choices": [
            {"message": {"role": "assistant", "content": "OpenAI generated text"}}
        ],
        "usage": {"prompt_tokens": 20, "completion_tokens": 30, "total_tokens": 50},
    }
    output, meta = command(
        "import json; print(json.dumps(" + repr(openai_payload) + "))",
        adapter="openai-json",
    ).generate("test")
    assert output == "OpenAI generated text"
    assert meta.model == "gpt-4o"
    assert meta.actual_provider == "openai"
    assert meta.adapter == "openai-json"
    assert meta.request_id == "chatcmpl-999"
    assert meta.usage == {"prompt_tokens": 20, "completion_tokens": 30, "total_tokens": 50}


def test_gemini_json_adapter():
    gemini_payload = {
        "candidates": [
            {"content": {"parts": [{"text": "Gemini generated text"}]}}
        ],
        "modelVersion": "gemini-2.0-flash",
        "usageMetadata": {"promptTokenCount": 15, "candidatesTokenCount": 25},
    }
    output, meta = command(
        "import json; print(json.dumps(" + repr(gemini_payload) + "))",
        adapter="gemini-json",
    ).generate("test")
    assert output == "Gemini generated text"
    assert meta.model == "gemini-2.0-flash"
    assert meta.actual_provider == "gemini"
    assert meta.adapter == "gemini-json"
    assert meta.usage == {"promptTokenCount": 15, "candidatesTokenCount": 25}


def test_unsupported_adapter_rejected():
    with pytest.raises(ProviderError, match="supported format"):
        CommandConfig((sys.executable, "-c", "pass"), True, adapter="unsupported-adapter")
