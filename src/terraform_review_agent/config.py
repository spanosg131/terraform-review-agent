"""Application configuration — loaded from environment / `.env`.

All settings are read once at process start via :class:`Settings`. Secrets are
never hardcoded; downstream modules (``llm.py``, ``github_client.py``, …) read
from :data:`settings` rather than from ``os.environ`` directly.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

LLMProvider = Literal["openai", "anthropic", "google"]
Environment = Literal["development", "staging", "production"]
# "none" disables CI gating; otherwise the run fails when a finding's severity
# meets or exceeds this floor. Mirrors `Severity` in utils.state plus "none".
FailOnSeverity = Literal["critical", "high", "medium", "low", "info", "none"]


class Settings(BaseSettings):
    """Process-wide configuration sourced from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        # Treat empty env values (`KEY=`) as unset so copying `.env.example`
        # doesn't crash int parsing or turn blank keys into SecretStr("").
        env_ignore_empty=True,
    )

    openai_api_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None
    google_api_key: SecretStr | None = None

    default_llm_provider: LLMProvider = "anthropic"
    default_llm_model: str = "claude-sonnet-4-5"
    default_llm_temperature: float = 0.0

    sqlite_path: str = "./data/state.sqlite"

    github_token: SecretStr | None = None
    github_repository: str | None = None
    github_pr_number: int | None = None
    github_api_url: str = "https://api.github.com"

    infracost_api_key: SecretStr | None = None
    infracost_baseline_path: str | None = None

    fail_on_severity: FailOnSeverity = "none"

    workspace_dir: str = "."

    langsmith_api_key: SecretStr | None = None
    langsmith_tracing: bool = False
    langsmith_project: str = "terraform-review-agent"

    log_level: str = "INFO"
    environment: Environment = "development"

    sticky_comment_marker: str = Field(
        default="<!-- terraform-review-agent:v1 -->",
        description="Hidden HTML marker used to find/upsert the bot's PR comment.",
    )

    def provider_key(self, provider: LLMProvider | None = None) -> SecretStr | None:
        """Return the API key for ``provider`` (defaults to the configured provider)."""

        target = provider or self.default_llm_provider
        if target == "openai":
            return self.openai_api_key
        if target == "anthropic":
            return self.anthropic_api_key
        if target == "google":
            return self.google_api_key
        raise ValueError(f"Unsupported LLM provider: {target!r}")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached :class:`Settings` singleton."""

    return Settings()


settings = get_settings()
