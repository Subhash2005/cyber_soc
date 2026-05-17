import asyncio
import json
import logging
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any
from .log_generator import start_log_generation
from .agent import process_logs
from .memory import memory_store

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="AI SOC Agent", description="Python-Native Cybersecurity SOC Backend")

# Allow CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory queue for logs
log_queue = asyncio.Queue()

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Error sending message to websocket: {e}")

manager = ConnectionManager()

@app.on_event("startup")
async def startup_event():
    # Initialize Memory Store
    memory_store.initialize()
    # Start log generation task
    asyncio.create_task(start_log_generation(log_queue))
    # Start the agent processing task
    asyncio.create_task(process_logs(log_queue, manager.broadcast))

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # We don't expect messages from the frontend in this basic version,
            # but we need to keep the connection open.
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("Client disconnected")

@app.get("/health")
def health_check():
    return {"status": "ok"}
