# backend/src/api/websocket.py
"""
WebSocket manager for real-time updates
"""

import asyncio
import json
import logging
from typing import Dict, Set, Any
from fastapi import WebSocket, WebSocketDisconnect
from datetime import datetime

logger = logging.getLogger(__name__)

class WebSocketManager:
    """Manage WebSocket connections and broadcast messages"""
    
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        self.connection_topics: Dict[WebSocket, Set[str]] = {}
    
    async def connect(self, websocket: WebSocket, client_id: str, topics: list = None):
        """Accept WebSocket connection"""
        await websocket.accept()
        
        if client_id not in self.active_connections:
            self.active_connections[client_id] = set()
        
        self.active_connections[client_id].add(websocket)
        self.connection_topics[websocket] = set(topics or [])
        
        logger.info(f"WebSocket connected: {client_id}, topics: {topics}")
        
        # Send connection confirmation
        await self.send_personal_message({
            "type": "connection",
            "status": "connected",
            "client_id": client_id,
            "timestamp": datetime.now().isoformat()
        }, websocket)
    
    async def disconnect(self, websocket: WebSocket, client_id: str):
        """Disconnect WebSocket"""
        if client_id in self.active_connections:
            self.active_connections[client_id].discard(websocket)
            if not self.active_connections[client_id]:
                del self.active_connections[client_id]
        
        if websocket in self.connection_topics:
            del self.connection_topics[websocket]
        
        logger.info(f"WebSocket disconnected: {client_id}")
    
    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """Send message to specific connection"""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Failed to send personal message: {e}")
    
    async def broadcast(self, topic: str, message: dict):
        """Broadcast message to all connections subscribed to topic"""
        message["timestamp"] = datetime.now().isoformat()
        message["topic"] = topic
        
        for client_id, connections in self.active_connections.items():
            for websocket in connections:
                if topic in self.connection_topics.get(websocket, set()):
                    try:
                        await websocket.send_json(message)
                    except Exception as e:
                        logger.error(f"Failed to broadcast to {client_id}: {e}")
    
    async def broadcast_to_client(self, client_id: str, message: dict):
        """Broadcast to all connections of a specific client"""
        if client_id in self.active_connections:
            for websocket in self.active_connections[client_id]:
                try:
                    await websocket.send_json(message)
                except Exception as e:
                    logger.error(f"Failed to send to {client_id}: {e}")
    
    def subscribe(self, websocket: WebSocket, topic: str):
        """Subscribe connection to topic"""
        if websocket in self.connection_topics:
            self.connection_topics[websocket].add(topic)
        else:
            self.connection_topics[websocket] = {topic}
    
    def unsubscribe(self, websocket: WebSocket, topic: str):
        """Unsubscribe connection from topic"""
        if websocket in self.connection_topics:
            self.connection_topics[websocket].discard(topic)


# Global instance
ws_manager = WebSocketManager()


async def websocket_endpoint(websocket: WebSocket, client_id: str = None):
    """WebSocket endpoint handler"""
    if not client_id:
        client_id = f"client_{id(websocket)}"
    
    topics = []
    
    # Parse query parameters for initial topics
    if websocket.query_params:
        topics_param = websocket.query_params.get("topics", "")
        if topics_param:
            topics = [t.strip() for t in topics_param.split(",")]
    
    await ws_manager.connect(websocket, client_id, topics)
    
    try:
        while True:
            # Receive message from client
            data = await websocket.receive_text()
            
            try:
                message = json.loads(data)
                msg_type = message.get("type")
                
                if msg_type == "subscribe":
                    topic = message.get("topic")
                    if topic:
                        ws_manager.subscribe(websocket, topic)
                        await ws_manager.send_personal_message({
                            "type": "subscribed",
                            "topic": topic,
                            "status": "success"
                        }, websocket)
                
                elif msg_type == "unsubscribe":
                    topic = message.get("topic")
                    if topic:
                        ws_manager.unsubscribe(websocket, topic)
                        await ws_manager.send_personal_message({
                            "type": "unsubscribed",
                            "topic": topic,
                            "status": "success"
                        }, websocket)
                
                elif msg_type == "ping":
                    await ws_manager.send_personal_message({
                        "type": "pong",
                        "timestamp": datetime.now().isoformat()
                    }, websocket)
                
                else:
                    # Echo back with processing info
                    await ws_manager.send_personal_message({
                        "type": "echo",
                        "received": message,
                        "processed_at": datetime.now().isoformat()
                    }, websocket)
                    
            except json.JSONDecodeError:
                await ws_manager.send_personal_message({
                    "type": "error",
                    "error": "Invalid JSON",
                    "timestamp": datetime.now().isoformat()
                }, websocket)
                
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket, client_id)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await ws_manager.disconnect(websocket, client_id)