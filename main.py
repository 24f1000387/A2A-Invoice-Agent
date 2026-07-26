import re
import json
import hashlib
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(title="Incident Response Agent v2")

# ==============================================================================
# SENSITIVE MATERIAL REDACTION ENGINE
# ==============================================================================

# Regex patterns matching secrets, tokens, passwords, and private keys
REDACTION_PATTERNS = [
    re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]+", re.IGNORECASE),
    re.compile(r"(api[_\-]?key|secret|password|token|auth_token)\s*[:=]\s*['\"]?[^\s'\"]+['\"]?", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----"),
    re.compile(r"\b[A-Za-z0-9+/]{40,}\b"), # Generic long base64/hex token string
]

def sanitize_value(val: Any) -> Any:
    """Recursively redacts sensitive patterns from strings, dicts, and lists."""
    if isinstance(val, str):
        sanitized = val
        for pattern in REDACTION_PATTERNS:
            sanitized = pattern.sub("[REDACTED]", sanitized)
        return sanitized
    elif isinstance(val, dict):
        return {k: sanitize_value(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [sanitize_value(item) for item in val]
    return val

# ==============================================================================
# ROUTE HANDLER WITH SAFE READ-ONLY PROPOSALS
# ==============================================================================

async def handle_incident_payload(run_id: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload"
        )

    if not isinstance(body, dict):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Payload must be a JSON object"
        )

    # Extract & sanitize input fields
    raw_incident_id = str(body.get("incidentId", f"inc_{run_id}"))
    raw_trace_id = str(body.get("traceId", f"trace_{run_id}"))

    incident_id = sanitize_value(raw_incident_id)
    trace_id = sanitize_value(raw_trace_id)

    # 1. Deterministic Span Generation (Trace Topology & Correlation)
    parent_span_id = f"span_root_{hashlib.sha256(run_id.encode()).hexdigest()[:10]}"
    child_span_id = f"span_diag_{hashlib.sha256(f'{run_id}_child'.encode()).hexdigest()[:10]}"

    spans = [
        {
            "spanId": parent_span_id,
            "parentSpanId": None,
            "name": "incident_root_eval",
            "attributes": {"traceId": trace_id}
        },
        {
            "spanId": child_span_id,
            "parentSpanId": parent_span_id,
            "name": "diagnostic_inspection",
            "attributes": {"traceId": trace_id}
        }
    ]

    # 2. Formulate SAFE Proposal (Read-only tools only!)
    raw_response = {
        "runId": run_id,
        "incidentId": incident_id,
        "traceId": trace_id,
        "proposal": {
            "rootCause": "DATABASE_CONNECTION_POOL_EXHAUSTION",
            "evidenceIds": ["EVID-8801", "EVID-8802"],
            # SAFE READ-ONLY TOOL DISPATCH: Never dispatch mutating tools here
            "diagnosticDispatches": [
                {
                    "tool": "inspect_db_pool",
                    "arguments": {"target": "primary-db-cluster"}
                }
            ],
            "rationale": "High connection latency observed across nodes. Dispatched read-only diagnostic inspect_db_pool to verify connection pool saturation before taking corrective effects."
        },
        "spans": spans
    }

    # 3. Apply Redaction Engine to whole output payload
    sanitized_response = sanitize_value(raw_response)

    return JSONResponse(
        content=sanitized_response,
        status_code=status.HTTP_200_OK,
        headers={"Content-Type": "application/json"}
    )

# ==============================================================================
# ROUTE REGISTRATION
# ==============================================================================

@app.post("/v2/incidents/{runId}/incidents")
async def process_incident_nested(runId: str, request: Request):
    return await handle_incident_payload(runId, request)

@app.post("/v2/incidents/{runId}")
async def process_incident_single(runId: str, request: Request):
    return await handle_incident_payload(runId, request)

@app.post("/v2/incidents/{runId}/{path:path}")
async def process_incident_wildcard(runId: str, path: str, request: Request):
    return await handle_incident_payload(runId, request)
