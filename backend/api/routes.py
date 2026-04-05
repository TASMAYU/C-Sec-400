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

# Request/Response models
class SimulateRequest(BaseModel):
    start_asset_id: str
    target_asset_id: str
    iterations: Optional[int] = 100

class PredictRequest(BaseModel):
    asset_id: str

# ========== ASSETS ==========
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

# ========== PATHFINDING ==========
@router.get("/paths")
async def find_paths(start: str, target: str):
    return pathfinder.find_paths(start, target)

# ========== PREDICTION & REMEDIATION ==========
@router.post("/predict")
async def predict_attack(request: PredictRequest):
    return predictor.predict_attack(request.asset_id)

@router.post("/remediate")
async def generate_playbook(request: PredictRequest):
    return remediator.generate_playbook(request.asset_id)

# ========== INCIDENTS & RCA ==========
@router.get("/incidents")
async def get_all_incidents():
    return tg.get_all_incidents()

@router.get("/incidents/{incident_id}/rca")
async def get_rca(incident_id: str):
    return rca.generate_rca(incident_id)

# ========== RED TEAM SIMULATION ==========
@router.post("/simulate")
async def run_simulation(request: SimulateRequest):
    return redteam.run_simulation(
        request.start_asset_id,
        request.target_asset_id,
        request.iterations
    )

# ========== CRITICAL RISKS ==========
@router.get("/critical-risks")
async def get_critical_risks():
    return tg.get_critical_risks()