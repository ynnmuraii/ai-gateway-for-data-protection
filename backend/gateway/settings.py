from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GATEWAY_", env_file=".env", extra="ignore")
    database_url: str = "postgresql+psycopg://gateway:gateway@127.0.0.1:55432/gateway"
    public_origin: str = "http://localhost:5173"
    csrf_secret: str = Field(min_length=32)
    pseudonym_secret: str = Field(min_length=32)
    identity_secret: str = Field(min_length=32)
    provider_secret: str = ""
    provider_secret_ref: str = "provider-default"
    provider_allowed_hosts: str = "api.openai.com"
    provider_base_url: str = Field(default="https://api.openai.com/v1", min_length=1, max_length=2048)
    provider_label: str = Field(default="OpenAI", min_length=1, max_length=128)
    provider_model: str = Field(default="gpt-4o-mini", min_length=1, max_length=128)
    demo_mode: bool = False
    detector_workers: int = 2
    detector_queue_size: int = 6
    detector_timeout_seconds: float = 5
    detector_queue_timeout_seconds: float = 5
    max_request_bytes: int = 262144
