import os
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext

from database import db, create_document, get_documents
from schemas import User as UserSchema, Event as EventSchema, Role as RoleSchema

try:
    from bson import ObjectId  # for safer _id operations
except Exception:
    ObjectId = None  # optional; we avoid relying on it at runtime

# Security setup
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key-change")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(title="Star Command Center API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utility models
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserPublic(BaseModel):
    id: Optional[str] = None
    username: str
    email: EmailStr
    roles: List[str]
    profile: Dict[str, Any] | None = None
    stats: Dict[str, Any] | None = None


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db["user"].find_one({"username": username}) if db else None
    if not user:
        raise credentials_exception
    return user


def require_roles(required: List[str]):
    async def inner(user: dict = Depends(get_current_user)):
        roles = user.get("roles", [])
        if not any(r in roles for r in required):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return inner


@app.get("/")
async def root():
    return {"status": "ok", "name": "Star Command Center API"}


@app.get("/test")
async def test_database():
    info = {
        "backend": "running",
        "database": "connected" if db else "not-configured",
        "collections": []
    }
    try:
        if db:
            info["collections"] = db.list_collection_names()
    except Exception as e:
        info["database"] = f"error: {str(e)[:100]}"
    return info


# Auth routes
class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str


@app.post("/auth/register", response_model=UserPublic)
async def register(payload: RegisterRequest):
    if not db:
        raise HTTPException(500, "Database not configured")
    if db["user"].find_one({"$or": [{"username": payload.username}, {"email": payload.email}] }):
        raise HTTPException(400, "Username or email already exists")
    user_doc = UserSchema(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
    ).model_dump()
    _ = create_document("user", user_doc)
    created = db["user"].find_one({"username": payload.username})
    return UserPublic(
        id=str(created.get("_id")),
        username=created["username"],
        email=created["email"],
        roles=created.get("roles", []),
        profile=created.get("profile"),
        stats=created.get("stats"),
    )


@app.post("/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if not db:
        raise HTTPException(500, "Database not configured")
    user = db["user"].find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user.get("hashed_password", "")):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    token = create_access_token({"sub": user["username"]})
    return Token(access_token=token)


# Events
@app.get("/events")
async def list_events(limit: int = 50):
    return get_documents("event", {}, limit)


class CreateEvent(BaseModel):
    title: str
    description: Optional[str] = None
    category: str = "operation"
    start_time: datetime
    end_time: datetime
    reminder_minutes: Optional[int] = 30


@app.post("/events")
async def create_event(payload: CreateEvent, user=Depends(require_roles(["admin", "officer"]))):
    ev = EventSchema(
        title=payload.title,
        description=payload.description,
        category=payload.category,
        start_time=payload.start_time,
        end_time=payload.end_time,
        reminder_minutes=payload.reminder_minutes,
        organizer_id=str(user.get("_id")),
        participants=[str(user.get("_id"))],
    )
    _id = create_document("event", ev)
    return {"inserted_id": _id}


# Roster
@app.get("/roster")
async def roster_list(role: Optional[str] = None):
    if role:
        return get_documents("user", {"roles": role}, 200)
    return get_documents("user", {}, 200)


# Roles and settings (admin)
@app.get("/admin/roles")
async def get_roles(user=Depends(require_roles(["admin"]))):
    return get_documents("role", {}, 100)


class CreateRole(BaseModel):
    key: str
    name: str
    permissions: List[str] = []
    color: Optional[str] = "#60a5fa"


@app.post("/admin/roles")
async def create_role(payload: CreateRole, user=Depends(require_roles(["admin"]))):
    role = RoleSchema(key=payload.key, name=payload.name, permissions=payload.permissions, color=payload.color)
    _id = create_document("role", role)
    return {"inserted_id": _id}


@app.get("/schema")
async def get_schema_definitions():
    return {"collections": ["user", "event", "role", "log", "setting"]}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
