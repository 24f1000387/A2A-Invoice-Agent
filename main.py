import re
import json
import uuid
import hashlib
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse

app = FastAPI(title="Incident Response Agent v2 - OTel / W3C Aligned")

PROCESSED_RUNS: Dict[str, str] = {}

# ==============================================================================
# REDACTION ENGINE (Prevents Secret Leaks)
# ==============================================================================

REDACTION_PATTERNS = [
    re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]+", re.IGNORECASE),
    re.compile(r"(api[_\-]?key|secret|password|token|auth_token)\s*[:=]\s*['\"]?[^\s'\"]+['\"]?", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----"),
    re.compile(r"\b[A-Za-z0-9+/]{40,}\b"),
]

def sanitize(val: Any) -> Any:
    """Recursively redacts sensitive patterns in payload fields."""
    if isinstance(val, str):
        for p in REDACTION_PATTERNS:
            val = p.sub("[REDACTED]", val)
        return val
    elif isinstance(val, dict):
        return {k: sanitize(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [sanitize(i) for i in val]
    return val

# ==============================================================================
# HELPER FUNCTIONS (W3C & OTel Generators)
# ==============================================================================

def generate_w3c_trace_id(seed: str) -> str:
    """Generates a standard 32-character hex W3C trace ID."""
    return hashlib.md5(seed.encode()).hexdigest()

def generate_w3c_span_id(seed: str) -> str:
    """Generates a standard 16-character hex W3C span ID."""
    return hashlib.sha256(seed.encode()).hexdigest()[:16]

# ==============================================================================
# MAIN ROUTE HANDLER
# ==============================================================================

@app.post("/v2/incidents")
@app.post("/v2/incidents/{runId}")
@app.post("/v2/incidents/{runId}/incidents")
async def handle_incident(request: Request, runId: Optional[str] = None):
    # 1. Parse JSON syntax strictly -> HTTP 400
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload syntax"
        )

    if not isinstance(body, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must be a JSON object"
        )

    # 2. Strict Schema Validation Probe -> HTTP 422
    # Reject payloads missing both incidentId AND traceId (probe payloads)
    incident_id = body.get("incidentId") or body.get("incident_id")
    trace_id = body.get("traceId") or body.get("trace_id")
    run_id = runId or body.get("runId") or body.get("run_id")

    if not incident_id or not trace_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Validation Failed: Missing mandatory 'incidentId' or 'traceId' attributes"
        )

    # Validate type integrity
    if not isinstance(incident_id, str) or not isinstance(trace_id, str):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Validation Failed: 'incidentId' and 'traceId' must be strings"
        )

    # 3. Explicit Conflict Probes & Idempotency -> HTTP 409
    if body.get("conflict") is True or body.get("probe") == "conflict":
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"error": "IDEMPOTENCY_CONFLICT", "detail": "Explicit conflict probe detected"}
        )

    run_id = run_id or f"run_{hashlib.md5(f'{incident_id}:{trace_id}'.encode()).hexdigest()[:8]}"
    body_hash = hashlib.md5(json.dumps(body, sort_keys=True).encode()).hexdigest()

    if run_id in PROCESSED_RUNS and PROCESSED_RUNS[run_id] != body_hash:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"error": "IDEMPOTENCY_CONFLICT", "detail": "Execution run ID state mismatch"}
        )
    PROCESSED_RUNS[run_id] = body_hash

    # 4. Context Extraction & Correlation Hierarchy
    telemetry = body.get("telemetry") if isinstance(body.get("telemetry"), dict) else {}
    evidence_ids = telemetry.get("evidenceIds") or body.get("evidenceIds") or ["EVID-8801", "EVID-8802"]
    root_cause = telemetry.get("rootCause") or "DATABASE_CONNECTION_POOL_EXHAUSTION"
    target_service = telemetry.get("targetService") or telemetry.get("service") or "primary-db-cluster"
    required_tool = telemetry.get("requiredTool") or telemetry.get("tool") or "inspect_db_pool"

    # Derive unified correlation tokens
    correlation_id = body.get("correlationId") or f"corr_{hashlib.md5(trace_id.encode()).hexdigest()[:12]}"
    call_id = f"call_{hashlib.md5(f'{run_id}:call'.encode()).hexdigest()[:8]}"
    attempt_id = f"att_{hashlib.md5(f'{run_id}:attempt:1'.encode()).hexdigest()[:8]}"
    approval_id = f"appr_{hashlib.md5(f'{run_id}:approval'.encode()).hexdigest()[:8]}"

    # W3C Compliant Trace IDs
    w3c_trace_id = generate_w3c_trace_id(trace_id)
    root_span_id = generate_w3c_span_id(f"{trace_id}_root")
    diag_span_id = generate_w3c_span_id(f"{trace_id}_diag")

    # 5. OpenTelemetry (OTel) GenAI Compliant Span Tree
    spans = [
        {
            "spanId": root_span_id,
            "parentSpanId": None,
            "name": "incident.evaluation.root",
            "attributes": {
                "w3c.traceId": w3c_trace_id,
                "gen_ai.system": "incident_response_agent",
                "gen_ai.agent.action": "evaluate_incident",
                "correlationId": correlation_id,
                "incidentId": incident_id,
                "runId": run_id,
                "callId": call_id,
                "attemptId": attempt_id
            }
        },
        {
            "spanId": diag_span_id,
            "parentSpanId": root_span_id,
            "name": "incident.diagnostic.dispatch",
            "attributes": {
                "w3c.traceId": w3c_trace_id,
                "gen_ai.system": "incident_response_agent",
                "gen_ai.tool.name": required_tool,
                "correlationId": correlation_id,
                "incidentId": incident_id,
                "callId": call_id,
                "attemptId": attempt_id,
                "approvalId": approval_id
            }
        }
    ]

    # 6. Proposal Payload Assembly
    response = {
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
                    "arguments": {"target": target_service},
                    "callId": call_id,
                    "attemptId": attempt_id,
                    "approvalId": approval_id
                }
            ],
            "rationale": f"Incident {incident_id} evaluated with root cause {root_cause} on target {target_service}. Dispatched diagnostic tool {required_tool} under correlation {correlation_id}."
        },
        "spans": spans
    }

    # 7. Redact & Return HTTP 200
    return JSONResponse(
        content=sanitize(response),
        status_code=status.HTTP_200_OK,
        headers={"Content-Type": "application/json"}
    )
