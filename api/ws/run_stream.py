"""
WebSocket live run stream endpoint (/ws/runs/{run_id}).
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()


@router.websocket("/ws/runs/{run_id}")
async def run_stream(websocket: WebSocket, run_id: str):
    await websocket.accept()
    try:
        await websocket.send_json({"type": "connected", "run_id": run_id})
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({"type": "ack", "message": data})
    except WebSocketDisconnect:
        pass
