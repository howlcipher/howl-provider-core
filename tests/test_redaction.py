from howl_provider_core import REDACTED, redact, scrub, secret_env_values


def test_known_token_shapes_and_assignments_are_redacted():
    text = (
        "key sk-abcdefghijklmnop gh token ghp_abcdefghijklmnopqrst pat github_pat_11AB "
        "aws AKIAABCDEFGHIJKLMNOP authorization: Bearer abc.def password=hunter2 api-key: x1 "
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"
    )
    out = redact(text)
    for leaked in ("sk-abc", "ghp_", "github_pat_", "AKIA", "abc.def", "hunter2", "x1", "MIIE"):
        assert leaked not in out, leaked
    assert out.count(REDACTED) >= 8


def test_literal_secrets_are_redacted_even_without_a_known_shape():
    assert (
        redact("my secret is plainvalue42", secrets=["plainvalue42"]) == "my secret is [REDACTED]"
    )
    assert redact("nothing", secrets=["", None or ""]) == "nothing"


def test_scrub_walks_json_and_drops_secret_keys():
    value = {
        "Authorization": "x",
        "nested": [{"token": "t", "note": "sk-abcdefghijklmnop"}],
        "n": 1,
    }
    assert scrub(value) == {
        "Authorization": REDACTED,
        "nested": [{"token": REDACTED, "note": REDACTED}],
        "n": 1,
    }


def test_secret_env_values_picks_credential_like_names():
    env = {"OPENAI_API_KEY": "k1", "GH_TOKEN": "t1", "PATH": "/usr/bin", "EMPTY_SECRET": ""}
    assert sorted(secret_env_values(env)) == ["k1", "t1"]


def test_historical_union_unknown_provider_credentials():
    # Synthetic provider echoes, deliberately absent from the environment.
    values = [
        "privateValue456",
        "opaqueCredential123",
        "abcdefghijkl-mnopqrstuvwxyz",
        "opaque+/credential==",
        "synthetic_password",
        "standalone.value-123456",
    ]
    echoes = [
        "token: bearer privateValue456",
        '"api_key": "Bearer opaqueCredential123"',
        "ghp_abcdefghijkl-mnopqrstuvwxyz",
        "secret_key='Bearer opaque+/credential=='",
        "passwd=synthetic_password",
        "Bearer standalone.value-123456",
    ]
    for echo, value in zip(echoes, values):
        assert value not in redact(echo)
        assert value not in str(scrub({"error": echo, "logs": [echo], "receipt": echo}))


def test_historical_writer_provider_token_shapes():
    for credential in (
        "AIza" + "A" * 32,
        "xoxb-synthetic-token-123456",
        "eyJsynthetic12.abcdef.signature123",
        "github_pat_abc_def-123456789",
    ):
        assert credential not in redact(credential)


def test_structured_secret_keys_cover_assignment_aliases():
    for key in ("api-key", "passwd", "secret_key", "bearer"):
        assert scrub({key: "syntheticPrivate456"}) == {key: REDACTED}


def test_historical_private_key_spacing_variants():
    text = "-----BEGINPRIVATE KEY-----syntheticPrivate456-----ENDPRIVATE KEY-----"
    assert "syntheticPrivate456" not in redact(text)
