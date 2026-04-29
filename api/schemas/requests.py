# ============================================================
# api/schemas/requests.py  —  Pydantic request models
# ============================================================
from __future__ import annotations
from pydantic import BaseModel, Field, field_validator


class RunAgentRequest(BaseModel):
    prompt:     str   = Field(..., min_length=1, max_length=4096,
                              description="User prompt to process through the secure pipeline")
    session_id: str   = Field("", max_length=64,
                              description="Optional session identifier for grouping requests")

    @field_validator("prompt")
    @classmethod
    def prompt_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Prompt must not be blank.")
        return v

    model_config = {"json_schema_extra": {
        "examples": [{"prompt": "What is the capital of France?", "session_id": "demo-001"}]
    }}


class LogsQueryParams(BaseModel):
    limit:       int  = Field(20,  ge=1,  le=200)
    since_hours: int  = Field(24,  ge=1,  le=720)