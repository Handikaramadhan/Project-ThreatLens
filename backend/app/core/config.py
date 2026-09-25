from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "ThreatLens"
    database_url: str = "postgresql+psycopg://threatlens:threatlens@postgres:5432/threatlens"
    redis_url: str = "redis://redis:6379/0"
    api_cors_origins: str = "http://localhost:8080,http://localhost:5173"
    nvd_api_key: str = ""
    urlhaus_auth_key: str = ""
    collector_window_days: int = 2
    news_retention_days: int = 180
    ioc_retention_days: int = 180
    collection_run_retention_days: int = 30
    collection_run_min_keep: int = 10
    seed_demo_data: bool = False
    auth_cookie_name: str = "threatlens_session"
    auth_cookie_secure: bool = False
    auth_session_hours: int = 12
    alert_secret_key: str = ""
    ai_enabled: bool = False
    ai_provider: str = ""
    ai_model: str = ""
    picoclaw_runner_url: str = "http://picoclaw-runner:8090"
    picoclaw_runner_token: str = ""
    picoclaw_timeout_seconds: int = 180
    ai_max_prompt_chars: int = 12000


settings = Settings()


def get_cors_origins() -> list[str]:
    return [origin.strip() for origin in settings.api_cors_origins.split(",") if origin.strip()]
