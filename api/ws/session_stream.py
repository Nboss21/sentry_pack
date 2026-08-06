"""
WebSocket C2 live session stream endpoint (/ws/sessions/{session_id}).
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()


@router.websocket("/ws/sessions/{session_id}")
async def session_stream(websocket: WebSocket, session_id: str):
    await websocket.accept()
    try:
        await websocket.send_json({"type": "session_connected", "session_id": session_id})
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({"type": "session_output", "data": data})
    except WebSocketDisconnect:
        pass
