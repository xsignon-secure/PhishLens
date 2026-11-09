"""AI providers for the assistant. Anthropic uses its own SDK; every other
provider is reached through the OpenAI-compatible chat completions API, which
almost all of them offer. "custom" takes any OpenAI-compatible endpoint
(LiteLLM, vLLM, LM Studio, Ollama, a company gateway...).

Model names change often, so the model is a free text field: `model` below is
only the suggestion shown in the dashboard."""
import urllib.parse

from .config import settings

PROVIDERS: dict[str, dict] = {
    "anthropic": {"label": "Anthropic (Claude)", "base_url": None, "model": "claude-opus-5-5",
                  "keys_url": "https://console.anthropic.com/settings/keys"},
    "openai": {"label": "OpenAI", "base_url": "https://api.openai.com/v1", "model": "gpt-4.1",
               "keys_url": "https://platform.openai.com/api-keys"},
    "gemini": {"label": "Google Gemini", "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
               "model": "gemini-2.5-flash", "keys_url": "https://aistudio.google.com/apikey"},
    "azure": {"label": "Azure OpenAI", "base_url": None, "model": "your-deployment-name", "needs_base_url": True,
              "base_hint": "https://YOUR-RESOURCE.openai.azure.com/openai/v1",
              "keys_url": "https://portal.azure.com/"},
    "mistral": {"label": "Mistral AI", "base_url": "https://api.mistral.ai/v1", "model": "mistral-large-latest",
                "keys_url": "https://console.mistral.ai/api-keys"},
    "deepseek": {"label": "DeepSeek", "base_url": "https://api.deepseek.com/v1", "model": "deepseek-chat",
                 "keys_url": "https://platform.deepseek.com/api_keys"},
    "xai": {"label": "xAI (Grok)", "base_url": "https://api.x.ai/v1", "model": "grok-4",
            "keys_url": "https://console.x.ai/"},
    "groq": {"label": "Groq", "base_url": "https://api.groq.com/openai/v1", "model": "llama-3.3-70b-versatile",
             "keys_url": "https://console.groq.com/keys"},
    "cohere": {"label": "Cohere", "base_url": "https://api.cohere.ai/compatibility/v1", "model": "command-a-03-2025",
               "keys_url": "https://dashboard.cohere.com/api-keys"},
    "together": {"label": "Together AI", "base_url": "https://api.together.xyz/v1",
                 "model": "meta-llama/Llama-3.3-70B-Instruct-Turbo", "keys_url": "https://api.together.ai/settings/api-keys"},
    "fireworks": {"label": "Fireworks AI", "base_url": "https://api.fireworks.ai/inference/v1",
                  "model": "accounts/fireworks/models/llama-v3p3-70b-instruct",
                  "keys_url": "https://fireworks.ai/account/api-keys"},
    "perplexity": {"label": "Perplexity", "base_url": "https://api.perplexity.ai", "model": "sonar-pro",
                   "keys_url": "https://www.perplexity.ai/settings/api"},
    "openrouter": {"label": "OpenRouter (hundreds of models)", "base_url": "https://openrouter.ai/api/v1",
                   "model": "openai/gpt-4.1", "keys_url": "https://openrouter.ai/keys"},
    "custom": {"label": "Other (any OpenAI-compatible endpoint)", "base_url": None, "model": "",
               "needs_base_url": True, "key_optional": True, "base_hint": "https://llm.example.com/v1"},
}


class ProviderError(ValueError):
    pass


def catalog() -> list[dict]:
    return [{"id": pid, "label": p["label"], "model": p["model"], "needs_base_url": bool(p.get("needs_base_url")),
             "key_optional": bool(p.get("key_optional")), "base_hint": p.get("base_hint"),
             "keys_url": p.get("keys_url")} for pid, p in PROVIDERS.items()]


def private_endpoints_allowed() -> bool:
    return settings.AI_ALLOW_PRIVATE_ENDPOINTS


def check_base_url(url: str) -> str:
    """Endpoints are typed in by users, so the server only calls https URLs on
    public hosts (unless a self-hoster turns on AI_ALLOW_PRIVATE_ENDPOINTS to
    reach, say, Ollama on their own network)."""
    from .scanner import net
    url = (url or "").strip().rstrip("/")
    parts = urllib.parse.urlparse(url)
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ProviderError("The endpoint URL can't contain a login, query or fragment")
    if private_endpoints_allowed():
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ProviderError("The endpoint must be an http(s):// URL")
        return url
    if parts.scheme != "https" or not parts.hostname:
        raise ProviderError("The endpoint must be an https:// URL")
    if not net.is_public_host(parts.hostname):
        raise ProviderError("The endpoint must be on a public host")
    return url


def resolve(provider: str, base_url: str | None) -> str | None:
    """The endpoint to call for an OpenAI-compatible provider."""
    p = PROVIDERS.get(provider)
    if not p:
        raise ProviderError("Unknown AI provider")
    if p.get("needs_base_url"):
        if not base_url:
            raise ProviderError(f"{p['label']} needs the endpoint URL")
        return check_base_url(base_url)
    return p["base_url"]
