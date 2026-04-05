from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from agents.pathfinder_agent import PathfinderAgent
from agents.predictor_agent import PredictorAgent
from agents.remediator_agent import RemediatorAgent
from agents.rca_agent import RCAAgent
from agents.red_team_agent import RedTeamAgent
from database.tigergraph_client import TigerGraphClient

router = APIRouter(prefix="/api", tags=["Cyber Defence"])

# Initialize agents and client
pathfinder = PathfinderAgent()
predictor = PredictorAgent()
remediator = RemediatorAgent()
rca = RCAAgent()
redteam = RedTeamAgent()
tg = TigerGraphClient()


# ========== REQUEST MODELS ==========

class PathRequest(BaseModel):
    start_asset_id: str
    target_asset_id: str

class PredictRequest(BaseModel):
    asset_id: str

class RemediateRequest(BaseModel):
    asset_id: str
    incident_context: Optional[str] = None

class RCARequest(BaseModel):
    incident_id: str

class SimulateRequest(BaseModel):
    start_asset_id: str
    target_asset_id: str
    iterations: Optional[int] = 100


# ========== ASSETS (GET - simple fetch) ==========

@router.get("/assets")
async def get_all_assets():
    return tg.get_all_assets()

@router.get("/assets/{asset_id}")
async def get_asset(asset_id: str):
    asset = tg.get_asset_by_id(asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    return asset

@router.get("/assets/{asset_id}/vulnerabilities")
async def get_asset_vulns(asset_id: str):
    return tg.get_asset_vulnerabilities(asset_id)


# ========== PATHFINDER AGENT (POST) ==========

@router.post("/pathfinder")
async def find_paths(request: PathRequest):
    """Find attack paths between two assets"""
    return pathfinder.find_paths(request.start_asset_id, request.target_asset_id)


# ========== PREDICTOR AGENT (POST) ==========

@router.post("/predictor")
async def predict_attack(request: PredictRequest):
    """Predict how an attacker could compromise an asset"""
    return predictor.predict_attack(request.asset_id)


# ========== REMEDIATOR AGENT (POST) ==========

@router.post("/remediator")
async def generate_playbook(request: RemediateRequest):
    """Generate remediation commands for a vulnerable asset"""
    return remediator.generate_playbook(request.asset_id, request.incident_context)


# ========== RCA AGENT (POST) ==========

@router.post("/rca")
async def get_rca(request: RCARequest):
    """Generate Root Cause Analysis report for an incident"""
    return rca.generate_rca(request.incident_id)


# ========== RED TEAM AGENT (POST) ==========

@router.post("/redteam")
async def run_simulation(request: SimulateRequest):
    """Run red team attack simulation"""
    return redteam.run_simulation(
        request.start_asset_id,
        request.target_asset_id,
        request.iterations
    )


# ========== INCIDENTS (GET - simple fetch) ==========

@router.get("/incidents")
async def get_all_incidents():
    return tg.get_all_incidents()

@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    incident = tg.get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident


# ========== CRITICAL RISKS (GET) ==========

@router.get("/critical-risks")
async def get_critical_risks():
    return tg.get_critical_risks()