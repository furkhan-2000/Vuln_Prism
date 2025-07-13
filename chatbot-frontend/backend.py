#!/usr/bin/env python3
"""
Simple Backend for Chatbot Frontend
Serves the main UI and handles DeepSeek API integration
"""

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import os
import httpx
import uvicorn

# Load environment variables
load_dotenv(".env")

app = FastAPI(title="VulnPrism Frontend & Chatbot")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: list[ChatMessage]
    max_tokens: int = 1024
    temperature: float = 0.7

@app.get("/")
async def serve_frontend():
    """Serve the main dashboard"""
    return FileResponse("index.html")

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.post("/chat")
async def chat_with_zoya(request: ChatRequest):
    """DeepSeek API integration"""
    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key or not api_key.strip():
        print("[ERROR] DeepSeek API key is missing or empty in .env file.")
        raise HTTPException(status_code=500, detail="API key not configured. Please check your .env file.")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://api.deepseek.com/v1/chat/completions",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}"
                },
                json={
                    "model": "deepseek-chat",
                    "messages": [{"role": msg.role, "content": msg.content} for msg in request.messages],
                    "max_tokens": request.max_tokens,
                    "temperature": request.temperature,
                    "stream": False
                },
                timeout=30.0
            )
            if response.status_code == 401:
                print("[ERROR] DeepSeek API key is invalid or unauthorized.")
                raise HTTPException(status_code=401, detail="DeepSeek API key is invalid or unauthorized.")
            if response.status_code == 429:
                print("[ERROR] DeepSeek API rate limit exceeded.")
                raise HTTPException(status_code=429, detail="DeepSeek API rate limit exceeded. Please try again later.")
            if response.status_code >= 500:
                print(f"[ERROR] DeepSeek server error: {response.status_code} {response.text}")
                raise HTTPException(status_code=502, detail="DeepSeek service is temporarily unavailable. Please try again later.")
            if response.status_code != 200:
                print("[ERROR] DeepSeek API error:", response.status_code, response.text)
                raise HTTPException(status_code=response.status_code, detail=response.text)
            try:
                data = response.json()
            except Exception as parse_err:
                print("[ERROR] Failed to parse DeepSeek response:", parse_err, response.text)
                raise HTTPException(status_code=500, detail="Failed to parse DeepSeek response.")
            if not data or "choices" not in data or not data["choices"]:
                print("[ERROR] DeepSeek API returned no choices.", data)
                raise HTTPException(status_code=500, detail="DeepSeek API returned no choices.")
            return data
    except httpx.RequestError as e:
        print("[ERROR] Network error calling DeepSeek:", e)
        raise HTTPException(status_code=502, detail="Network error calling DeepSeek API.")
    except Exception as e:
        print("[ERROR] DeepSeek exception:", e)
        raise HTTPException(status_code=500, detail="Internal server error.")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=3000)
