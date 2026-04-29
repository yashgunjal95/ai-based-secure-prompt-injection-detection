# ============================================================
# api/schemas/responses.py  —  Pydantic response models
# ============================================================
from __future__ import annotations
from typing import Any, Optional
from pydantic import BaseModel


class LayerScoresOut(BaseModel):
    rule_based:    float
    ml_classifier: float
    llm_validator: float


class DecisionOut(BaseModel):
    decision_id:    str
    final_score:    float
    weighted_score: float
    decision:       str
    is_threat:      bool
    reasons:        list[str]
    overrides_fired:list[str]
    layer_scores:   LayerScoresOut
    rule_matches:   int
    rule_categories:list[str]
    ml_label:       str
    llm_verdict:    str
    llm_attack:     str


class AgentOut(BaseModel):
    output:       str
    tools_used:   list[str]
    step_count:   int
    exec_ms:      float
    success:      bool


class RunAgentResponse(BaseModel):
    request_id:  str
    session_id:  str
    routing:     str                     # allow | sanitize | block
    completed:   bool
    final_output:str
    decision:    Optional[DecisionOut]   = None
    agent:       Optional[AgentOut]      = None
    node_timings:dict[str, float]        = {}
    total_ms:    float
    errors:      list[str]               = []


class HealthResponse(BaseModel):
    status:      str
    version:     str
    environment: str
    components:  dict[str, Any]
    uptime_s:    float


class PipelineStatusResponse(BaseModel):
    ml_classifier: dict[str, Any]
    llm_validator: dict[str, Any]
    agent:         dict[str, Any]
    log_stats:     dict[str, Any]


class LogsSummaryResponse(BaseModel):
    total_requests:        int
    decisions:             dict[str, int]
    rates:                 dict[str, float]
    performance:           dict[str, float]
    top_attack_categories: list
    top_attack_types:      list
    top_decision_reasons:  list
    recent_blocks:         list
    time_range:            dict[str, str]
    error_count:           int


class ThreatEntry(BaseModel):
    timestamp:   Optional[str]
    request_id:  Optional[str]
    routing:     Optional[str]
    prompt:      Optional[str]
    final_score: Optional[float]
    reasons:     list[str] = []
    attack_type: Optional[str]
    categories:  list[str] = []


class ErrorResponse(BaseModel):
    error:   str
    detail:  str = ""
    code:    int = 500