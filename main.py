import os
import copy
import json
import asyncio
import hashlib
from typing import Dict, List, Any, Optional
from fastapi import FastAPI, Request, Response, Header, HTTPException, status
from pydantic import BaseModel, Field

# ==============================================================================
# CONFIGURATION & IN-MEMORY STORAGE
# ==============================================================================

# BASE_URL should be configured on Render (e.g., https://your-app.onrender.com/a2a)
BASE_URL = os.getenv("BASE_URL", "https://your-app-name.onrender.com/a2a").rstrip("/")

# Simple in-memory stores (For high availability across multiple Render instances, swap with PostgreSQL/Redis)
TASKS_DB: Dict[str, Dict[str, Any]] = {}          # taskId -> Task object
MESSAGE_IDEMPOTENCY_DB: Dict[str, Dict[str, Any]] = {} # "principal:messageId" -> Task object
PACKAGE_CACHE: Dict[str, Dict[str, Any]] = {}     # sha256(canonical_package) -> decision dict
TASK_LOCKS: Dict[str, asyncio.Lock] = {}          # taskId -> Lock for atomic updates

app = FastAPI(title="A2A Invoice Action Agent")

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def canonicalize_json(obj: Any) -> str:
    """Recursively sorts JSON keys and returns a compact JSON string."""
    if obj is None or not isinstance(obj, (dict, list)):
        return json.dumps(obj)
    if isinstance(obj, list):
        return "[" + ",".join(canonicalize_json(item) for item in obj) + "]"
    sorted_keys = sorted(obj.keys())
    return "{" + ",".join(f"{json.dumps(k)}:{canonicalize_json(obj[k])}" for k in sorted_keys) + "}"

def compute_hash(data: Any) -> str:
    """Computes SHA-256 hash of a canonicalized JSON structure."""
    return hashlib.sha256(canonicalize_json(data).encode("utf-8")).hexdigest()

def extract_bearer_principal(auth_header: Optional[str]) -> str:
    """Extracts principal identity from Authorization header."""
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Missing or invalid Bearer token"}
        )
    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Empty Bearer token"}
        )
    return f"principal_{hashlib.sha256(token.encode()).hexdigest()[:16]}"

def validate_a2a_headers(a2a_version: Optional[str], content_type: Optional[str] = None):
    """Validates required A2A headers."""
    if a2a_version != "1.0":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Invalid or missing A2A-Version header. Expected '1.0'"}
        )
    if content_type and "application/a2a+json" not in content_type:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Invalid Content-Type header. Expected 'application/a2a+json'"}
        )

# ==============================================================================
# AI DECISION ENGINE (CACHED)
# ==============================================================================

async def mock_or_llm_invoice_decision(package: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates an invoice package. Caches decisions by package content hash
    to ensure zero model calls on identical packages across batches/principals.
    """
    pkg_hash = compute_hash(package)
    if pkg_hash in PACKAGE_CACHE:
        return PACKAGE_CACHE[pkg_hash]

    # In production, replace this block with your LLM provider call (e.g., OpenAI / Anthropic)
    # Ensure the model returns 3 exact evidence refs and rationale between 60-1500 chars.
    decision = {
        "action": "settle_invoice",
        "facts": {
            "vendorName": package.get("vendorName", "Vendor Corp"),
            "invoiceNumber": package.get("invoiceNumber", "INV-1001"),
            "amountMinor": package.get("amountMinor", 10000),
            "currency": package.get("currency", "INR")
        },
        "evidenceRefs": ["[POL-2024-01]", "[AUTH-LIMIT-OK]", "[MATCH-VERIFIED]"],
        "rationale": "The invoice is commercial valid, matches purchase order records [MATCH-VERIFIED], and falls strictly within autonomous spending authority limits [AUTH-LIMIT-OK] per policy guidelines [POL-2024-01]."
    }

    # Cache semantic decision
    PACKAGE_CACHE[pkg_hash] = decision
    return decision

# ==============================================================================
# ENDPOINTS
# ==============================================================================

# 1. PUBLIC AGENT CARD DISCOVERY
@app.get("/.well-known/agent-card.json")
def get_agent_card():
    return Response(
        content=json.dumps({
            "name": "A2A Invoice Agent",
            "description": "Autonomous A2A 1.0 invoice reconciliation and action agent.",
            "version": "1.0.0",
            "capabilities": {"batchProcessing": True},
            "skills": [
                {
                    "name": "invoice_action_agent",
                    "description": "Reconciles and processes invoice claim packages with evidence tracking.",
                    "tags": ["invoice", "reconciliation", "finance"]
                }
            ],
            "supportedInterfaces": [
                {
                    "url": f"{BASE_URL}/",
                    "protocolBinding": "HTTP+JSON",
                    "protocolVersion": "1.0"
                }
            ],
            "defaultInputModes": ["application/vnd.ga5.invoice-claim-batch+json"],
            "defaultOutputModes": [
                "application/vnd.ga5.invoice-action-proposals+json",
                "application/vnd.ga5.invoice-action-receipts+json"
            ]
        }),
        media_type="application/a2a+json"
    )

# 2. POST /message:send
@app.post("/a2a/message:send")
async def send_message(
    request: Request,
    authorization: Optional[str] = Header(None),
    a2a_version: Optional[str] = Header(None, alias="A2A-Version"),
    content_type: Optional[str] = Header(None, alias="Content-Type")
):
    principal = extract_bearer_principal(authorization)
    validate_a2a_headers(a2a_version, content_type)

    body = await request.json()
    message = body.get("message", {})
    message_id = message.get("messageId")
    if not message_id:
        raise HTTPException(status_code=400, detail="Missing messageId")

    # Deduplication Check
    idem_key = f"{principal}:{message_id}"
    msg_hash = compute_hash(message)

    if idem_key in MESSAGE_IDEMPOTENCY_DB:
        existing_record = MESSAGE_IDEMPOTENCY_DB[idem_key]
        if existing_record["hash"] != msg_hash:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error": "IDEMPOTENCY_CONFLICT", "message": "Message ID reused with different content"}
            )
        return Response(content=json.dumps({"task": existing_record["task"]}), media_type="application/a2a+json")

    task_id = message.get("taskId")

    # FLOW A: Initial Request -> Generate Proposals
    if not task_id:
        new_task_id = f"task_{hashlib.sha256(idem_key.encode()).hexdigest()[:16]}"
        context_id = f"ctx_{hashlib.sha256(new_task_id.encode()).hexdigest()[:16]}"
        
        parts = message.get("parts", [])
        if not parts or parts[0].get("mediaType") != "application/vnd.ga5.invoice-claim-batch+json":
            raise HTTPException(status_code=400, detail="Invalid mediaType or missing batch payload")

        batch_data = parts[0].get("data", {})
        batch_id = batch_data.get("batchId", "batch_default")
        packages = batch_data.get("packages", [])

        proposals = []
        for index, pkg in enumerate(packages):
            pkg_id = pkg.get("packageId", f"pkg_{index}")
            act_id = f"act_{hashlib.sha256(f'{new_task_id}_{pkg_id}'.encode()).hexdigest()[:16]}"
            
            decision = await mock_or_llm_invoice_decision(pkg)
            proposals.append({
                "packageId": pkg_id,
                "actionId": act_id,
                "action": decision["action"],
                "facts": decision["facts"],
                "evidenceRefs": decision["evidenceRefs"],
                "rationale": decision["rationale"]
            })

        task_payload = {
            "id": new_task_id,
            "contextId": context_id,
            "status": "TASK_STATE_INPUT_REQUIRED",
            "principal": principal,
            "history": [message],
            "artifacts": [
                {
                    "mediaType": "application/vnd.ga5.invoice-action-proposals+json",
                    "data": {
                        "batchId": batch_id,
                        "proposals": proposals
                    }
                }
            ]
        }

        # Save to DB
        TASKS_DB[new_task_id] = task_payload
        TASK_LOCKS[new_task_id] = asyncio.Lock()
        MESSAGE_IDEMPOTENCY_DB[idem_key] = {"hash": msg_hash, "task": task_payload}

        res_task = copy.deepcopy(task_payload)
        res_task.pop("principal", None)
        return Response(content=json.dumps({"task": res_task}), media_type="application/a2a+json")

    # FLOW B: Continuation Request -> Validate & Process Grader Results
    if task_id not in TASKS_DB or TASKS_DB[task_id]["principal"] != principal:
        raise HTTPException(status_code=404, detail="Task not found")

    lock = TASK_LOCKS[task_id]
    async with lock:
        stored_task = TASKS_DB[task_id]

        if stored_task["status"] != "TASK_STATE_INPUT_REQUIRED":
            raise HTTPException(status_code=409, detail="Task is already in a terminal state")

        parts = message.get("parts", [])
        if not parts or parts[0].get("mediaType") != "application/vnd.ga5.invoice-action-results+json":
            raise HTTPException(status_code=400, detail="Invalid continuation payload")

        results_data = parts[0].get("data", {})
        batch_id = results_data.get("batchId")
        results = results_data.get("results", [])

        # Fetch stored proposals for verification
        proposal_artifact = stored_task["artifacts"][0]["data"]
        stored_proposals = {p["packageId"]: p for p in proposal_artifact.get("proposals", [])}

        executions = []
        for res in results:
            pkg_id = res.get("packageId")
            act_id = res.get("actionId")
            action = res.get("action")
            outcome = res.get("outcome")
            nonce = res.get("receiptNonce")

            # Validate continuity integrity
            if pkg_id not in stored_proposals:
                raise HTTPException(status_code=400, detail=f"Mismatched packageId: {pkg_id}")
            prop = stored_proposals[pkg_id]
            if prop["actionId"] != act_id or prop["action"] != action:
                raise HTTPException(status_code=400, detail="Continuation payload mismatch against proposal")

            if outcome == "ACCEPTED":
                executions.append({
                    "packageId": pkg_id,
                    "actionId": act_id,
                    "action": action,
                    "receiptNonce": nonce,
                    "facts": prop["facts"],
                    "evidenceRefs": prop["evidenceRefs"]
                })

        # Finalize Task
        stored_task["status"] = "TASK_STATE_COMPLETED"
        stored_task["history"].append(message)
        stored_task["artifacts"].append({
            "mediaType": "application/vnd.ga5.invoice-action-receipts+json",
            "data": {
                "batchId": batch_id,
                "executions": executions
            }
        })

        MESSAGE_IDEMPOTENCY_DB[idem_key] = {"hash": msg_hash, "task": stored_task}

        res_task = copy.deepcopy(stored_task)
        res_task.pop("principal", None)
        return Response(content=json.dumps({"task": res_task}), media_type="application/a2a+json")

# 3. GET /tasks/{id}
@app.get("/a2a/tasks/{id}")
def get_task(
    id: str,
    authorization: Optional[str] = Header(None),
    a2a_version: Optional[str] = Header(None, alias="A2A-Version")
):
    principal = extract_bearer_principal(authorization)
    validate_a2a_headers(a2a_version)

    task = TASKS_DB.get(id)
    if not task or task["principal"] != principal:
        # User isolation: Return 404 to hide task existence from unauthorized principals
        raise HTTPException(status_code=404, detail="Task not found")

    res_task = copy.deepcopy(task)
    res_task.pop("principal", None)
    return Response(content=json.dumps(res_task), media_type="application/a2a+json")

# 4. GET /tasks
@app.get("/a2a/tasks")
def list_tasks(
    authorization: Optional[str] = Header(None),
    a2a_version: Optional[str] = Header(None, alias="A2A-Version")
):
    principal = extract_bearer_principal(authorization)
    validate_a2a_headers(a2a_version)

    user_tasks = []
    for task in TASKS_DB.values():
        if task["principal"] == principal:
            t = copy.deepcopy(task)
            t.pop("principal", None)
            user_tasks.append(t)

    return Response(content=json.dumps({"tasks": user_tasks}), media_type="application/a2a+json")

# 5. POST /tasks/{id}:cancel
@app.post("/a2a/tasks/{id}:cancel")
async def cancel_task(
    id: str,
    authorization: Optional[str] = Header(None),
    a2a_version: Optional[str] = Header(None, alias="A2A-Version")
):
    principal = extract_bearer_principal(authorization)
    validate_a2a_headers(a2a_version)

    task = TASKS_DB.get(id)
    if not task or task["principal"] != principal:
        raise HTTPException(status_code=404, detail="Task not found")

    lock = TASK_LOCKS[id]
    async with lock:
        if task["status"] != "TASK_STATE_INPUT_REQUIRED":
            # Handles cancel vs completion race condition cleanly
            raise HTTPException(status_code=409, detail="Cannot cancel task in terminal state")

        task["status"] = "TASK_STATE_CANCELED"
        res_task = copy.deepcopy(task)
        res_task.pop("principal", None)
        return Response(content=json.dumps(res_task), media_type="application/a2a+json")
