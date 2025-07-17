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
import os
import httpx
import uvicorn

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
        print("[ERROR] DEEPSEEK_API_KEY environment variable is not set.")
        raise HTTPException(status_code=500, detail="API key not configured.")

    # Optional: Set your site URL and title for OpenRouter rankings
    site_url = "https://your-site-url.com"  # Change to your actual site URL if desired
    site_title = "VulnPrism"  # Change to your actual site title if desired

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": site_url,
                    "X-Title": site_title
                },
                json={
                    "model": "openai/gpt-4o",
                    "messages": [{"role": msg.role, "content": msg.content} for msg in request.messages],
                    "max_tokens": request.max_tokens,
                    "temperature": request.temperature
                },
                timeout=30.0
            )
            if response.status_code == 401:
                print("[ERROR] OpenRouter API key is invalid or unauthorized.")
                raise HTTPException(status_code=401, detail="OpenRouter API key is invalid or unauthorized.")
            if response.status_code == 429:
                print("[ERROR] OpenRouter API rate limit exceeded.")
                raise HTTPException(status_code=429, detail="OpenRouter API rate limit exceeded. Please try again later.")
            if response.status_code >= 500:
                print(f"[ERROR] OpenRouter server error: {response.status_code} {response.text}")
                raise HTTPException(status_code=502, detail="OpenRouter service is temporarily unavailable. Please try again later.")
            if response.status_code != 200:
                print("[ERROR] OpenRouter API error:", response.status_code, response.text)
                raise HTTPException(status_code=response.status_code, detail=response.text)
            try:
                data = response.json()
            except Exception as parse_err:
                print("[ERROR] Failed to parse OpenRouter response:", parse_err, response.text)
                raise HTTPException(status_code=500, detail="Failed to parse OpenRouter response.")
            if not data or "choices" not in data or not data["choices"]:
                print("[ERROR] OpenRouter API returned no choices.", data)
                raise HTTPException(status_code=500, detail="OpenRouter API returned no choices.")
            return data
    except httpx.RequestError as e:
        print("[ERROR] Network error calling OpenRouter:", e)
        raise HTTPException(status_code=502, detail="Network error calling OpenRouter API.")
    except Exception as e:
        print("[ERROR] OpenRouter exception:", e)
        raise HTTPException(status_code=500, detail="Internal server error.")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=3000)
