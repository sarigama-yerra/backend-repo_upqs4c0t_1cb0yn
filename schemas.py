"""
Database Schemas for Attendance App

Each Pydantic model corresponds to a MongoDB collection (lowercased class name).

Collections:
- User: registered users (students/faculty/admin)
- Attendance: attendance events
- Session: class/session QR tokens created by faculty
"""
from pydantic import BaseModel, Field
from typing import Optional, Literal, List
from datetime import datetime

class User(BaseModel):
    full_name: str = Field(..., description="Full Name")
    department: str = Field(..., description="Department")
    class_section: str = Field(..., description="Class / Section")
    username: str = Field(..., description="Unique username")
    password_hash: str = Field(..., description="BCrypt password hash")
    student_id: Optional[str] = Field(None, description="Optional Student ID")
    photo_url: Optional[str] = Field(None, description="Optional photo URL for profile avatar")
    face_encrypted: Optional[bytes] = Field(None, description="Encrypted face image bytes (Fernet)")
    face_phash: Optional[str] = Field(None, description="Perceptual hash for basic matching")
    role: Literal['student','faculty','admin'] = Field('student', description="Role")
    approved: bool = Field(False, description="Whether registration is approved by admin/faculty")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Attendance(BaseModel):
    user_id: str = Field(..., description="User ObjectId as string")
    method: Literal['face','qr_self','qr_session'] = Field(..., description="Marking method")
    lat: Optional[float] = Field(None, description="Latitude for geofence check")
    lng: Optional[float] = Field(None, description="Longitude for geofence check")
    inside_geofence: bool = Field(False, description="Whether within geofence")
    status: Literal['present','rejected'] = Field('present', description="Attendance status")
    reason: Optional[str] = Field(None, description="Rejection reason if any")
    metadata: Optional[dict] = Field(None, description="Additional info like session_id, class")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Session(BaseModel):
    creator_id: str = Field(..., description="Faculty/Admin user id")
    department: str = Field(..., description="Department context")
    class_section: str = Field(..., description="Class/Section")
    expires_at: datetime = Field(..., description="Expiry timestamp")
    token_id: str = Field(..., description="Unique id referenced by QR JWT")
    active: bool = Field(True, description="Whether session still active")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
