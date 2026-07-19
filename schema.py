from pydantic import BaseModel
from typing import Literal, Optional
from datetime import datetime

class ChatbotCreate(BaseModel):
    name: str
    prompt: str
    model: Literal["qwen/qwen3.6-27b", "llama-3.1-8b-instant"]

class UploadDocument(BaseModel):
    file_name: str
    upload_at: datetime

class UserLogin(BaseModel):
    email: str
    password: str

class UserSignUp(BaseModel):
    name: str
    email: str
    password: str
    confirmed_password: str

class CheckEmail(BaseModel):
    email: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str


class UpdateChatbotInformation(BaseModel):
    name: str
    prompt: str
    model: Literal["qwen/qwen3.6-27b", "llama-3.1-8b-instant"]

class InputMessages(BaseModel):
    message: str
    sender: str

class Judul(BaseModel):
    judul: str


class VerifCode(BaseModel):
    email: str