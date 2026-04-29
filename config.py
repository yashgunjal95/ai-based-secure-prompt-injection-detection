# ============================================================
# config.py  —  Centralized environment-driven configuration.
#
# .env key conventions used by this project:
#   GROQ__API_KEY          → settings.groq.api_key
#   GROQ__MODEL_NAME       → settings.groq.model_name
#   BLOCK_THRESHOLD        → settings.detection.block_threshold
#   … etc.
# ============================================================
from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent

# ── Manually load .env into os.environ BEFORE any BaseSettings ──────────────
# This is the most reliable cross-platform approach. pydantic-settings sometimes
# struggles with nested prefixes on Windows when the file is loaded lazily.
_ENV_FILE = BASE_DIR / ".env"
if _ENV_FILE.exists():
    for _line in _ENV_FILE.read_text(encoding="utf-8").splitlines():
        _line = _line.strip()
        if not _line or _line.startswith("#") or "=" not in _line:
            continue
        _k, _, _v = _line.partition("=")
        _k = _k.strip()
        _v = _v.strip()
        # Strip surrounding quotes if present  e.g.  KEY="value"  or  KEY='value'
        if len(_v) >= 2 and _v[0] == _v[-1] and _v[0] in ('"', "'"):
            _v = _v[1:-1]
        os.environ.setdefault(_k, _v)


# ---------------------------------------------------------------------------
# Sub-settings
# ---------------------------------------------------------------------------

class GroqSettings(BaseSettings):
    """
    Groq LLM connection settings.

    Reads both GROQ__API_KEY (double-underscore, nested style) and
    GROQ_API_KEY (single-underscore, flat style) from the environment.
    The alias 'GROQ__API_KEY' matches pydantic-settings nested delimiter
    convention; model_post_init provides a belt-and-suspenders fallback.
    """

    # Use the exact env key as the alias so pydantic-settings finds it directly
    api_key:    str = Field(default="", alias="GROQ__API_KEY")
    model_name: str = Field(default="llama-3.3-70b-versatile", alias="GROQ__MODEL_NAME")

    model_config = SettingsConfigDict(
        env_file             = str(_ENV_FILE),
        env_file_encoding    = "utf-8",
        extra                = "ignore",
        protected_namespaces = (),
        populate_by_name     = True,   # allow access by field name AND alias
    )

    def model_post_init(self, __context):
        # Belt-and-suspenders: also check flat GROQ_API_KEY variant
        if not self.api_key:
            self.api_key = os.environ.get("GROQ_API_KEY", "")
        if not self.model_name:
            self.model_name = os.environ.get(
                "GROQ_MODEL_NAME", "llama-3.3-70b-versatile"
            )


class DetectionSettings(BaseSettings):
    """Thresholds and weights for the three-layer detection pipeline."""

    rule_based_weight:    float = Field(0.30, alias="RULE_BASED_WEIGHT")
    ml_classifier_weight: float = Field(0.35, alias="ML_CLASSIFIER_WEIGHT")
    llm_validator_weight: float = Field(0.35, alias="LLM_VALIDATOR_WEIGHT")
    block_threshold:      float = Field(0.65, alias="BLOCK_THRESHOLD")
    sanitize_threshold:   float = Field(0.40, alias="SANITIZE_THRESHOLD")

    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE), extra="ignore"
    )

    @field_validator("block_threshold", "sanitize_threshold")
    @classmethod
    def must_be_probability(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("Threshold must be between 0.0 and 1.0")
        return v


class MLClassifierSettings(BaseSettings):
    """Settings for the ML classifier."""

    base_model:      str  = Field("distilbert-base-uncased", alias="CLASSIFIER_BASE_MODEL")
    classifier_path: Path = Field(
        BASE_DIR / "models" / "classifier" / "fine_tuned",
        alias="CLASSIFIER_MODEL_PATH",
    )
    label_map:        dict[int, str] = {0: "safe", 1: "injection"}
    max_token_length: int            = 512

    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE), extra="ignore",
        protected_namespaces=(),
    )


class APISettings(BaseSettings):
    """FastAPI server settings."""

    host:       str  = Field("0.0.0.0",                               alias="API_HOST")
    port:       int  = Field(8000,                                    alias="API_PORT")
    debug:      bool = Field(False,                                   alias="API_DEBUG")
    secret_key: str  = Field("change_this_to_a_strong_random_secret", alias="API_SECRET_KEY")
    allowed_origins: list[str] = ["*"]

    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE), extra="ignore"
    )


class LoggingSettings(BaseSettings):
    """Audit logging configuration."""

    level:     Literal["DEBUG","INFO","WARNING","ERROR","CRITICAL"] = Field(
        "INFO", alias="LOG_LEVEL"
    )
    file_path: Path = Field(BASE_DIR / "logs" / "audit.log", alias="LOG_FILE_PATH")
    rotation:  str  = Field("10 MB",   alias="LOG_ROTATION")
    retention: str  = Field("30 days", alias="LOG_RETENTION")

    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE), extra="ignore"
    )


# ---------------------------------------------------------------------------
# Master settings
# ---------------------------------------------------------------------------

class Settings(BaseSettings):
    """
    Master settings object — import this singleton everywhere:

        from config import settings
    """

    groq:          GroqSettings          = Field(default_factory=GroqSettings)
    detection:     DetectionSettings     = Field(default_factory=DetectionSettings)
    ml_classifier: MLClassifierSettings  = Field(default_factory=MLClassifierSettings)
    api:           APISettings           = Field(default_factory=APISettings)
    logging:       LoggingSettings       = Field(default_factory=LoggingSettings)

    project_name: str = "AI-Based Secure Prompt Injection Detection System"
    version:      str = "1.0.0"
    environment:  Literal["development","staging","production"] = "development"

    model_config = SettingsConfigDict(
        env_file          = str(_ENV_FILE),
        env_file_encoding = "utf-8",
        extra             = "ignore",
    )

    def is_production(self) -> bool:
        return self.environment == "production"


# ── Singleton ────────────────────────────────────────────────
settings = Settings()