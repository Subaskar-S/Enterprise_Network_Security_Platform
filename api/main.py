#!/usr/bin/env python3
"""
Enterprise Security Platform - API Gateway
FastAPI-based API gateway for the security platform
"""

from fastapi import FastAPI, HTTPException, Depends, status, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import jwt
import bcrypt
from pydantic import BaseModel, Field
import redis.asyncio as redis
from elasticsearch import AsyncElasticsearch
import json
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Enterprise Security Platform API",
    description="API Gateway for Enterprise Network Security Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3001", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Security
security = HTTPBearer()
SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"

# Global connections
redis_client = None
es_client = None
websocket_connections: List[WebSocket] = []

# Pydantic Models
class LoginRequest(BaseModel):
    username: str
    password: str

class User(BaseModel):
    id: str
    username: str
    email: str
    role: str
    permissions: List[str]

class ThreatAlert(BaseModel):
    id: Optional[str] = None
    timestamp: str
    severity: str
    type: str
    source_ip: str
    destination_ip: str
    description: str
    status: str = "open"
    risk_score: int

class SecurityIncident(BaseModel):
    id: Optional[str] = None
    title: str
    description: str
    severity: str
    status: str = "open"
    source_ip: str
    target_ip: str
    threat_type: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

class DashboardMetrics(BaseModel):
    totalThreats: int
    activeIncidents: int
    blockedIPs: int
    systemHealth: int
    threatTrends: Dict[str, int]
    networkStats: Dict[str, Any]
    complianceScore: int
    lastUpdated: str

# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    global redis_client, es_client
    
    # Initialize Redis
    redis_client = redis.Redis(host='localhost', port=6379, db=0)
    
    # Initialize Elasticsearch
    es_client = AsyncElasticsearch(['http://localhost:9200'])
    
    logger.info("API Gateway started successfully")

@app.on_event("shutdown")
async def shutdown_event():
    global redis_client, es_client
    
    if redis_client:
        await redis_client.close()
    
    if es_client:
        await es_client.close()
    
    logger.info("API Gateway shutdown complete")

# Authentication functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(username: str = Depends(verify_token)) -> User:
    # In production, this would query a real user database
    user_data = {
        "id": "1",
        "username": username,
        "email": f"{username}@enterprise.com",
        "role": "admin",
        "permissions": ["read", "write", "admin"]
    }
    return User(**user_data)

# WebSocket manager
class WebSocketManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                # Remove dead connections
                self.active_connections.remove(connection)

websocket_manager = WebSocketManager()

# API Routes

# Health check
@app.get("/api/v1/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

# Authentication endpoints
@app.post("/api/v1/auth/login")
async def login(login_request: LoginRequest):
    # In production, verify against real user database
    if login_request.username == "admin" and login_request.password == "admin":
        access_token = create_access_token(data={"sub": login_request.username})
        user_data = {
            "id": "1",
            "username": login_request.username,
            "email": f"{login_request.username}@enterprise.com",
            "role": "admin",
            "permissions": ["read", "write", "admin"]
        }
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": user_data
        }
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/api/v1/auth/logout")
async def logout(current_user: User = Depends(get_current_user)):
    return {"message": "Logged out successfully"}

@app.get("/api/v1/auth/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    return current_user

# Dashboard endpoints
@app.get("/api/v1/dashboard/metrics", response_model=DashboardMetrics)
async def get_dashboard_metrics(current_user: User = Depends(get_current_user)):
    # In production, this would query real data from Elasticsearch
    metrics = DashboardMetrics(
        totalThreats=42,
        activeIncidents=7,
        blockedIPs=156,
        systemHealth=98,
        threatTrends={
            "critical": 3,
            "high": 12,
            "medium": 18,
            "low": 9
        },
        networkStats={
            "totalTraffic": "2.4 TB",
            "blockedTraffic": "45 GB",
            "latency": 1.2,
            "throughput": "8.5 Gbps"
        },
        complianceScore=94,
        lastUpdated=datetime.now().isoformat()
    )
    return metrics

@app.get("/api/v1/dashboard/health")
async def get_system_health(current_user: User = Depends(get_current_user)):
    return {
        "elasticsearch": {"status": "healthy", "response_time": 15},
        "redis": {"status": "healthy", "response_time": 2},
        "suricata": {"status": "healthy", "alerts_per_second": 12},
        "ai_detection": {"status": "healthy", "predictions_per_second": 45}
    }

# Threat detection endpoints
@app.get("/api/v1/threats/alerts")
async def get_threat_alerts(
    page: int = 1,
    limit: int = 50,
    severity: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    # Mock data - in production, query Elasticsearch
    alerts = [
        {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "severity": "high",
            "type": "malware_detection",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.1.50",
            "description": "Malware communication detected",
            "status": "open",
            "risk_score": 85
        },
        {
            "id": str(uuid.uuid4()),
            "timestamp": (datetime.now() - timedelta(minutes=5)).isoformat(),
            "severity": "medium",
            "type": "brute_force",
            "source_ip": "203.0.113.100",
            "destination_ip": "10.0.1.22",
            "description": "Multiple failed login attempts",
            "status": "investigating",
            "risk_score": 65
        }
    ]
    
    return {
        "data": alerts,
        "total": len(alerts),
        "page": page,
        "limit": limit
    }

@app.post("/api/v1/threats/block-ip")
async def block_ip(
    ip_data: dict,
    current_user: User = Depends(get_current_user)
):
    ip_address = ip_data.get("ip")
    reason = ip_data.get("reason", "Blocked by security platform")
    
    # In production, this would call pfSense API
    logger.info(f"Blocking IP {ip_address}: {reason}")
    
    # Broadcast to WebSocket clients
    await websocket_manager.broadcast(json.dumps({
        "type": "ip_blocked",
        "data": {"ip": ip_address, "reason": reason},
        "timestamp": datetime.now().isoformat()
    }))
    
    return {"success": True, "message": f"IP {ip_address} blocked successfully"}

# Incident response endpoints
@app.get("/api/v1/incidents")
async def get_incidents(
    page: int = 1,
    limit: int = 50,
    status: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    # Mock data
    incidents = [
        {
            "id": str(uuid.uuid4()),
            "title": "Critical Malware Detection",
            "description": "Advanced malware detected on multiple systems",
            "severity": "critical",
            "status": "investigating",
            "source_ip": "192.168.1.100",
            "target_ip": "10.0.1.50",
            "threat_type": "malware",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
    ]
    
    return {
        "data": incidents,
        "total": len(incidents),
        "page": page,
        "limit": limit
    }

@app.post("/api/v1/incidents")
async def create_incident(
    incident: SecurityIncident,
    current_user: User = Depends(get_current_user)
):
    incident.id = str(uuid.uuid4())
    incident.created_at = datetime.now().isoformat()
    incident.updated_at = datetime.now().isoformat()
    
    # In production, store in database
    logger.info(f"Created incident: {incident.title}")
    
    # Broadcast to WebSocket clients
    await websocket_manager.broadcast(json.dumps({
        "type": "incident_created",
        "data": incident.dict(),
        "timestamp": datetime.now().isoformat()
    }))
    
    return incident

# Network endpoints
@app.get("/api/v1/network/topology")
async def get_network_topology(current_user: User = Depends(get_current_user)):
    # Mock network topology data
    topology = {
        "nodes": [
            {
                "id": "firewall-1",
                "label": "pfSense Firewall",
                "type": "firewall",
                "ip_address": "10.0.1.1",
                "status": "online"
            },
            {
                "id": "switch-1",
                "label": "Core Switch",
                "type": "switch",
                "ip_address": "10.0.1.2",
                "status": "online"
            },
            {
                "id": "server-1",
                "label": "Web Server",
                "type": "server",
                "ip_address": "10.0.1.100",
                "status": "online"
            }
        ],
        "edges": [
            {"from": "firewall-1", "to": "switch-1"},
            {"from": "switch-1", "to": "server-1"}
        ]
    }
    return topology

# Compliance endpoints
@app.get("/api/v1/compliance/reports/{framework}")
async def get_compliance_report(
    framework: str,
    current_user: User = Depends(get_current_user)
):
    # Mock compliance report
    report = {
        "framework": framework,
        "overall_score": 0.94,
        "last_assessment": datetime.now().isoformat(),
        "controls": [
            {
                "id": "CC6.1",
                "name": "Logical and Physical Access Controls",
                "status": "compliant",
                "score": 1.0
            },
            {
                "id": "CC6.2",
                "name": "System Access Controls",
                "status": "compliant",
                "score": 0.95
            }
        ]
    }
    return report

# WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            
            if message.get("type") == "ping":
                await websocket.send_text(json.dumps({
                    "type": "pong",
                    "timestamp": datetime.now().isoformat()
                }))
            else:
                # Echo message to all clients
                await websocket_manager.broadcast(data)
                
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": exc.detail, "status_code": exc.status_code}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
