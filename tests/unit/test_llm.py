"""Model factory, capability checks (mocked HTTP) and agent-output parsing."""

import httpx
import pytest
from agents import OpenAIChatCompletionsModel
from agents.models.openai_responses import OpenAIResponsesModel

from docker_security_agent.agents.security_assessment import parse_assessment_text
from docker_security_agent.config import ConfigError, ModelProfile
from docker_security_agent.llm.capabilities import check_profile, list_ollama_models, parse_num_ctx
from docker_security_agent.llm.factory import build_model

# ---------------------------------------------------------------------------
# factory
# ---------------------------------------------------------------------------


def test_ollama_and_vllm_use_chat_completions():
    for provider in ("ollama", "vllm"):
        p = ModelProfile(
            name="x", provider=provider, model="m", base_url="http://h:1/v1", temperature=0.1
        )
        bundle = build_model(p)
        assert isinstance(bundle.model, OpenAIChatCompletionsModel)
        assert bundle.settings.temperature == 0.1


def test_openai_uses_responses_and_needs_key(monkeypatch):
    p = ModelProfile(name="o", provider="openai", model="gpt-x", api_key_env="OPENAI_API_KEY")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(ConfigError, match="OPENAI_API_KEY"):
        build_model(p)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-real")
    assert isinstance(build_model(p).model, OpenAIResponsesModel)


def test_local_provider_requires_base_url():
    with pytest.raises(ConfigError, match="base_url"):
        build_model(ModelProfile(name="x", provider="vllm", model="m"))


# ---------------------------------------------------------------------------
# capability checks with a fake HTTP server
# ---------------------------------------------------------------------------

OLLAMA_TAGS = {
    "models": [
        {
            "name": "qwen3:14b-ctx32k",
            "size": 9_300_000_000,
            "details": {
                "family": "qwen3",
                "parameter_size": "14.8B",
                "quantization_level": "Q4_K_M",
            },
        },
        {"name": "dolphin3:latest", "size": 4_900_000_000, "details": {"family": "llama"}},
    ]
}
OLLAMA_SHOW = {
    "qwen3:14b-ctx32k": {
        "capabilities": ["completion", "tools", "thinking"],
        "parameters": "num_ctx                        32768\ntop_k 20",
    },
    "dolphin3:latest": {"capabilities": ["completion"], "parameters": 'stop "<|im_end|>"'},
}


def _ollama_transport(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/api/tags":
        return httpx.Response(200, json=OLLAMA_TAGS)
    if request.url.path == "/api/show":
        model = httpx.Request("POST", "/", content=request.content).read()
        name = __import__("json").loads(model)["model"]
        return httpx.Response(200, json=OLLAMA_SHOW.get(name, {}))
    if request.url.path == "/v1/models":
        return httpx.Response(200, json={"data": [{"id": "Qwen/Qwen3-14B"}]})
    return httpx.Response(404)


@pytest.fixture
def http():
    return httpx.AsyncClient(transport=httpx.MockTransport(_ollama_transport))


def _ollama(model):
    return ModelProfile(
        name="p", provider="ollama", model=model, base_url="http://localhost:11434/v1"
    )


async def test_ollama_tool_capable_model(http):
    r = await check_profile(_ollama("qwen3:14b-ctx32k"), http_client=http)
    assert r.ok and r.supports_tools is True and not r.warnings


async def test_ollama_model_without_tools_is_refused(http):
    r = await check_profile(_ollama("dolphin3"), http_client=http)  # ':latest' implied
    assert r.model_available and r.supports_tools is False and not r.ok
    assert any("does not support tool calling" in e for e in r.errors)
    assert any("Context window 4096" in w for w in r.warnings)


async def test_ollama_missing_model(http):
    r = await check_profile(_ollama("llama3.3:70b"), http_client=http)
    assert not r.ok and "ollama pull llama3.3:70b" in r.errors[0]


async def test_ollama_discovery(http):
    models = await list_ollama_models("http://localhost:11434/v1", client=http)
    assert [m.name for m in models] == ["qwen3:14b-ctx32k", "dolphin3:latest"]
    assert models[0].supports_tools and models[0].num_ctx == 32768
    assert not models[1].supports_tools and models[1].num_ctx is None


async def test_vllm_model_listing(http):
    p = ModelProfile(
        name="v", provider="vllm", model="Qwen/Qwen3-14B", base_url="http://localhost:8000/v1"
    )
    r = await check_profile(p, http_client=http)
    assert r.ok and r.supports_tools is None  # unknown until --probe
    p.model = "other"
    assert not (await check_profile(p, http_client=http)).ok


async def test_unreachable_provider():
    def boom(request):
        raise httpx.ConnectError("refused")

    async with httpx.AsyncClient(transport=httpx.MockTransport(boom)) as client:
        r = await check_profile(_ollama("qwen3"), http_client=client)
    assert not r.ok and "not reachable" in r.errors[0]


def test_parse_num_ctx():
    assert parse_num_ctx({"parameters": "num_ctx 8192\ntemperature 0.6"}) == 8192
    assert parse_num_ctx({"parameters": "temperature 0.6"}) is None


# ---------------------------------------------------------------------------
# prompted-mode output parsing
# ---------------------------------------------------------------------------

VALID = (
    '{"executive_summary":"s","overall_risk":"high","findings":[],'
    '"recommendations":["r"],"limitations":[]}'
)


@pytest.mark.parametrize(
    "text",
    [
        VALID,
        f"<think>let me reason {{not json}}</think>\n{VALID}",
        f"Here you go:\n```json\n{VALID}\n```\nDone.",
    ],
)
def test_parse_assessment_text(text):
    assert parse_assessment_text(text).overall_risk == "high"


def test_parse_assessment_text_rejects_garbage():
    with pytest.raises(ValueError):
        parse_assessment_text("I could not finish.")
    with pytest.raises(ValueError):  # pydantic ValidationError is a ValueError
        parse_assessment_text('{"executive_summary": "missing fields"}')
