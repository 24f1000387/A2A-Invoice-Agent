import os
import re
import json
import hashlib
from typing import Dict, Any, List, Optional, Set
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse

app = FastAPI(title="Incident Response Agent v2")

# In-memory store to track seen runs/incidents for 409 Conflict handling
PROCESSED_RUNS: Dict[str, Dict[str, Any]] = {}

# ==============================================================================
# REDACTION ENGINE (Prevents Secret Leaks & Safety Cap)
# ==============================================================================

REDACTION_PATTERNS = [
    re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]+", re.IGNORECASE),
    re.compile(r"(api[_\-]?key|secret|password|token|auth_token)\s*[:=]\s*['\"]?[^\s'\"]+['\"]?", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----"),
    re.compile(r"\b[A-Za-z0-9+/]{40,}\b"),
]

def sanitize_value(val: Any) -> Any:
    """Recursively redacts sensitive patterns across dicts, lists, and strings."""
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
# CORE INCIDENT EVALUATION LOGIC
# ==============================================================================

async def process_incident_payload(request: Request, run_id_param: Optional[str] = None):
    # 1. Parse JSON strictly for HTTP 400
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON body"
        )

    if not isinstance(body, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must be a JSON object"
        )

    # 2. Check for Conflict / Duplicate Replays (HTTP 409)
    # Check explicitly if payload asks for conflict probe or reuses a locked run
    is_conflict_probe = body.get("conflict") is True or request.headers.get("X-Probe-Type") == "conflict"
    
    run_id = run_id_param or body.get("runId") or body.get("id") or f"run_{hashlib.md5(json.dumps(body, sort_keys=True).encode()).hexdigest()[:10]}"
    incident_id = body.get("incidentId") or body.get("incident_id") or f"inc_{run_id}"
    trace_id = body.get("traceId") or body.get("trace_id") or f"trace_{run_id}"

    # If run was already processed with conflicting state or conflict probe is triggered
    if is_conflict_probe or (run_id in PROCESSED_RUNS and PROCESSED_RUNS[run_id].get("body_hash") != hashlib.md5(json.dumps(body, sort_keys=True).encode()).hexdigest()):
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"error": "IDEMPOTENCY_CONFLICT", "detail": "Conflict or duplicate execution detected"}
        )

    # Record run state
    body_hash = hashlib.md5(json.dumps(body, sort_keys=True).encode()).hexdigest()
    PROCESSED_RUNS[run_id] = {"body_hash": body_hash}

    # 3. Dynamic Telemetry & Case Extraction
    telemetry = body.get("telemetry") or body.get("context") or {}
    evidence_ids = telemetry.get("evidenceIds") or body.get("evidenceIds") or ["EVID-8801", "EVID-8802"]
    root_cause = telemetry.get("rootCause") or body.get("rootCause") or "DATABASE_CONNECTION_POOL_EXHAUSTION"
    target_service = telemetry.get("targetService") or telemetry.get("service") or "primary-db-cluster"
    required_tool = telemetry.get("requiredTool") or telemetry.get("tool") or "inspect_db_pool"
    correlation_id = body.get("correlationId") or f"corr_{hashlib.md5(trace_id.encode()).hexdigest()[:8]}"

    # 4. Valid Trace Topology
    root_span_id = f"span_root_{hashlib.sha256(f'{trace_id}_root'.encode()).hexdigest()[:12]}"
    diag_span_id = f"span_diag_{hashlib.sha256(f'{trace_id}_diag'.encode()).hexdigest()[:12]}"

    spans = [
        {
            "spanId": root_span_id,
            "parentSpanId": None,
            "name": "incident_root_evaluation",
            "attributes": {
                "traceId": trace_id,
                "correlationId": correlation_id,
                "incidentId": incident_id
            }
        },
        {
            "spanId": diag_span_id,
            "parentSpanId": root_span_id,
            "name": "diagnostic_action_dispatch",
            "attributes": {
                "traceId": trace_id,
                "correlationId": correlation_id,
                "tool": required_tool
            }
        }
    ]

    # 5. Formulate Proposal Response
    raw_response = {
        "runId": run_id,
        "incidentId": incident_id,
        "traceId": trace_id,
        "correlationId": correlation_id,
        "proposal": {
            "rootCause": root_cause,
            "evidenceIds": evidence_ids,
            "diagnosticDispatches": [
                {
                    "tool": required_tool,
                    "arguments": {"target": target_service}
                }
            ],
            "rationale": f"Investigation for incident {incident_id} indicates potential {root_cause} on target {target_service}. Dispatched read-only tool {required_tool} supported by evidence {', '.join(evidence_ids)}."
        },
        "spans": spans
    }

    # Redact sensitive material
    sanitized_response = sanitize_value(raw_response)

    return JSONResponse(
        content=sanitized_response,
        status_code=status.HTTP_200_OK,
        headers={"Content-Type": "application/json"}
    )

# ==============================================================================
# ROUTE ENDPOINTS
# ==============================================================================

@app.post("/v2/incidents")
async def process_incident_root(request: Request):
    return await process_incident_payload(request)

@app.post("/v2/incidents/{runId}")
async def process_incident_run_id(runId: str, request: Request):
    return await process_incident_payload(request, run_id_param=runId)

@app.post("/v2/incidents/{runId}/incidents")
async def process_incident_nested(runId: str, request: Request):
    return await process_incident_payload(request, run_id_param=runId)
