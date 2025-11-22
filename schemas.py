"""
Database Schemas for Command Center

Each Pydantic model below maps to a MongoDB collection whose name is the lowercase of the class name
(e.g., User -> "user"). These models are used for validation of inbound data.
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime

class UserProfile(BaseModel):
    handle: Optional[str] = Field(None, description="Public codename/handle")
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    banner_url: Optional[str] = None

class Availability(BaseModel):
    weekdays: List[int] = Field(default_factory=list, description="0-6 for Mon-Sun")
    time_blocks: List[str] = Field(default_factory=list, description="e.g., 18:00-21:00Z")

class Stats(BaseModel):
    missions_completed: int = 0
    flight_hours: float = 0
    rating: float = 0

class User(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    email: EmailStr
    hashed_password: str
    roles: List[str] = Field(default_factory=lambda: ["member"])  # e.g., admin, officer, member
    two_factor_enabled: bool = False
    oauth_providers: List[str] = Field(default_factory=list)
    profile: UserProfile = Field(default_factory=UserProfile)
    availability: Availability = Field(default_factory=Availability)
    stats: Stats = Field(default_factory=Stats)
    is_active: bool = True

class Event(BaseModel):
    title: str
    description: Optional[str] = None
    category: str = Field("operation", description="operation | training | social | other")
    start_time: datetime
    end_time: datetime
    reminder_minutes: Optional[int] = 30
    organizer_id: Optional[str] = None
    participants: List[str] = Field(default_factory=list)
    visibility: str = Field("org", description="org | public | private")

class Role(BaseModel):
    key: str = Field(..., description="unique key, e.g., admin, officer, pilot")
    name: str
    permissions: List[str] = Field(default_factory=list)
    color: Optional[str] = "#60a5fa"

class Log(BaseModel):
    type: str = Field(..., description="auth | system | roster | event | admin")
    actor_id: Optional[str] = None
    action: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

class Setting(BaseModel):
    key: str
    value: Any
    scope: str = Field("global", description="global | user:{id}")
