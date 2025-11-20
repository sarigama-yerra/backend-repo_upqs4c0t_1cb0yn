import os
import io
import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Body, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from database import db, create_document, get_documents
from schemas import User as UserSchema, Attendance as AttendanceSchema, Session as SessionSchema

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

FACE_ENC_KEY = os.getenv("FACE_ENC_KEY")
if not FACE_ENC_KEY:
    derived = base64.urlsafe_b64encode((SECRET_KEY * 2)[:32].encode())
    FACE_ENC_KEY = derived.decode()

# Geofence config
COLLEGE_LAT = float(os.getenv("COLLEGE_LAT", "12.9716"))
COLLEGE_LNG = float(os.getenv("COLLEGE_LNG", "77.5946"))
GEOFENCE_RADIUS_M = float(os.getenv("GEOFENCE_RADIUS_M", "300.0"))

# -----------------------------------------------------------------------------
# Password hashing (pure Python PBKDF2-SHA256)
# -----------------------------------------------------------------------------
PBKDF2_ITERATIONS = 240_000

def hash_password(password: str) -> str:
    if not isinstance(password, str):
        raise ValueError("password must be str")
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return "pbkdf2_sha256$%d$%s$%s" % (
        PBKDF2_ITERATIONS,
        salt.hex(),
        dk.hex(),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iter_s, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iter_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False

# -----------------------------------------------------------------------------
# Lazy import helpers
# -----------------------------------------------------------------------------
_jwt = None

def _get_jwt():
    global _jwt
    if _jwt is None:
        try:
            import jwt as pyjwt  # PyJWT
            _jwt = pyjwt
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"JWT library not available: {e}")
    return _jwt

_fernet_obj = None

def _get_fernet():
    global _fernet_obj
    if _fernet_obj is None:
        try:
            from cryptography.fernet import Fernet
            key = FACE_ENC_KEY
            _fernet_obj = Fernet(key)
        except Exception:
            _fernet_obj = False  # mark unavailable
    return _fernet_obj


def encrypt_bytes(data: bytes) -> bytes:
    f = _get_fernet()
    if f:
        return f.encrypt(data)
    return b"B64:" + base64.b64encode(data)


def decrypt_bytes(data: bytes) -> bytes:
    f = _get_fernet()
    if f:
        return f.decrypt(data)
    if data.startswith(b"B64:"):
        return base64.b64decode(data[4:])
    return data


def phash_from_image_bytes(data: bytes) -> str:
    try:
        from PIL import Image
        import imagehash
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Image libraries not available: {e}")
    image = Image.open(io.BytesIO(data)).convert("RGB").resize((256, 256))
    return str(imagehash.phash(image))

# -----------------------------------------------------------------------------
# JWT helpers
# -----------------------------------------------------------------------------

def create_access_token(user_id: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "role": role,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    return _get_jwt().encode(payload, SECRET_KEY, algorithm=JWT_ALG)


def create_reset_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "type": "reset",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
    }
    return _get_jwt().encode(payload, SECRET_KEY, algorithm=JWT_ALG)


def decode_token(token: str) -> dict:
    try:
        return _get_jwt().decode(token, SECRET_KEY, algorithms=[JWT_ALG])
    except Exception as e:
        from fastapi import HTTPException as _HTTPException
        if "Expired" in str(e):
            raise _HTTPException(status_code=401, detail="Token expired")
        raise _HTTPException(status_code=401, detail="Invalid token")


def require_auth(credentials: HTTPAuthorizationCredentials = Depends(security)):
    payload = decode_token(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")
    return payload

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def to_object_id(id_str: str):
    from bson import ObjectId
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")


def haversine_m(lat1, lon1, lat2, lon2):
    from math import radians, cos, sin, asin, sqrt
    R = 6371000.0
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat/2)**2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a))
    return R * c


def check_geofence(lat: Optional[float], lng: Optional[float]) -> bool:
    if lat is None or lng is None:
        return False
    dist = haversine_m(lat, lng, COLLEGE_LAT, COLLEGE_LNG)
    return dist <= GEOFENCE_RADIUS_M

# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    full_name: str
    department: str
    class_section: str
    username: str
    password: str
    student_id: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class ForgotRequest(BaseModel):
    username: str

class ResetRequest(BaseModel):
    token: str
    new_password: str

class UpdateProfileRequest(BaseModel):
    full_name: Optional[str] = None
    department: Optional[str] = None
    class_section: Optional[str] = None
    student_id: Optional[str] = None

class Geopoint(BaseModel):
    lat: Optional[float] = None
    lng: Optional[float] = None

class QRSessionCreate(BaseModel):
    department: str
    class_section: str
    minutes_valid: int = 10

# -----------------------------------------------------------------------------
# Core Routes
# -----------------------------------------------------------------------------
@app.get("/")
def root():
    return {"message": "Attendance Backend Running"}

@app.get("/test")
def test_database():
    info = {
        "backend": "ok",
        "db": False,
        "collections": []
    }
    try:
        if db is not None:
            info["db"] = True
            info["collections"] = db.list_collection_names()
    except Exception as e:
        info["error"] = str(e)
    return info

# ---------------------- Auth ----------------------
@app.post("/auth/register")
def register(req: RegisterRequest):
    if db["user"].find_one({"username": req.username}):
        raise HTTPException(status_code=400, detail="Username already exists")
    user = UserSchema(
        full_name=req.full_name,
        department=req.department,
        class_section=req.class_section,
        username=req.username,
        password_hash=hash_password(req.password),
        student_id=req.student_id,
        role='student',
        approved=False,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc)
    )
    user_id = create_document("user", user)
    return {"user_id": user_id, "approved": False}

@app.post("/auth/login")
def login(req: LoginRequest):
    u = db["user"].find_one({"username": req.username})
    if not u:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(req.password, u.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(str(u["_id"]), u.get("role", "student"))
    return {"access_token": token, "approved": u.get("approved", False), "role": u.get("role", "student")}

@app.post("/auth/forgot")
def forgot(req: ForgotRequest):
    u = db["user"].find_one({"username": req.username})
    if not u:
        return {"status": "ok"}
    reset_token = create_reset_token(str(u["_id"]))
    return {"reset_token": reset_token}

@app.post("/auth/reset")
def reset(req: ResetRequest):
    payload = decode_token(req.token)
    if payload.get("type") != "reset":
        raise HTTPException(status_code=400, detail="Invalid reset token")
    user_id = payload.get("sub")
    db["user"].update_one({"_id": to_object_id(user_id)}, {"$set": {"password_hash": hash_password(req.new_password), "updated_at": datetime.now(timezone.utc)}})
    return {"status": "password-updated"}

# ---------------------- Profile ----------------------
@app.get("/me")
def get_me(auth=Depends(require_auth)):
    u = db["user"].find_one({"_id": to_object_id(auth["sub"])}, {"password_hash": 0, "face_encrypted": 0})
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    u["_id"] = str(u["_id"])
    return u

@app.put("/me")
def update_me(req: UpdateProfileRequest, auth=Depends(require_auth)):
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    if updates:
        updates["updated_at"] = datetime.now(timezone.utc)
        db["user"].update_one({"_id": to_object_id(auth["sub"])}, {"$set": updates})
    return {"status": "updated"}

class FaceUpload(BaseModel):
    image_base64: str

@app.post("/me/photo")
async def upload_face(payload: FaceUpload, auth=Depends(require_auth)):
    try:
        data = base64.b64decode(payload.image_base64.split(",")[-1])
        ph = phash_from_image_bytes(data)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid image")
    enc = encrypt_bytes(data)
    db["user"].update_one(
        {"_id": to_object_id(auth["sub"])},
        {"$set": {"face_encrypted": enc, "face_phash": ph, "updated_at": datetime.now(timezone.utc)}}
    )
    return {"status": "face-updated"}

# ---------------------- QR Tools ----------------------
@app.post("/qr/self")
def generate_self_qr(geo: Geopoint = Body(None), auth=Depends(require_auth)):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": auth["sub"],
        "type": "qr_self",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }
    if geo and geo.lat and geo.lng:
        payload["lat"] = geo.lat
        payload["lng"] = geo.lng
    token = _get_jwt().encode(payload, SECRET_KEY, algorithm=JWT_ALG)
    return {"qr_token": token}

@app.post("/qr/session")
def generate_session_qr(req: QRSessionCreate, auth=Depends(require_auth)):
    if auth.get("role") not in ["faculty", "admin"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    now = datetime.now(timezone.utc)
    token_id = base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")
    session = SessionSchema(
        creator_id=auth["sub"],
        department=req.department,
        class_section=req.class_section,
        expires_at=now + timedelta(minutes=req.minutes_valid),
        token_id=token_id,
        active=True,
        created_at=now,
        updated_at=now,
    )
    session_id = create_document("session", session)
    payload = {
        "type": "qr_session",
        "sid": session_id,
        "tid": token_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=req.minutes_valid)).timestamp()),
    }
    token = _get_jwt().encode(payload, SECRET_KEY, algorithm=JWT_ALG)
    return {"qr_token": token, "session_id": session_id}

# ---------------------- Attendance ----------------------
class FaceMarkBody(BaseModel):
    image_base64: str
    lat: Optional[float] = None
    lng: Optional[float] = None

class QRMarkRequest(BaseModel):
    qr_token: str
    lat: Optional[float] = None
    lng: Optional[float] = None

@app.post("/attendance/mark/face")
async def mark_attendance_face(body: FaceMarkBody, auth=Depends(require_auth)):
    u = db["user"].find_one({"_id": to_object_id(auth["sub"])})
    if not u or not u.get("face_phash"):
        raise HTTPException(status_code=400, detail="No face on file. Upload in profile first")
    try:
        data = base64.b64decode(body.image_base64.split(",")[-1])
        ph = phash_from_image_bytes(data)
        import imagehash  # lazy import
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid image")
    stored_ph = u.get("face_phash")
    try:
        dist = imagehash.hex_to_hash(ph) - imagehash.hex_to_hash(stored_ph)
    except Exception:
        dist = 9999
    inside = check_geofence(body.lat, body.lng)
    if dist <= 10 and inside:
        att = AttendanceSchema(
            user_id=str(u["_id"]),
            method='face',
            lat=body.lat, lng=body.lng, inside_geofence=True,
            status='present', reason=None,
            metadata=None,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        att_id = create_document("attendance", att)
        return {"status": "marked", "attendance_id": att_id, "method": "face"}
    else:
        att = AttendanceSchema(
            user_id=str(u["_id"]),
            method='face',
            lat=body.lat, lng=body.lng, inside_geofence=inside,
            status='rejected', reason=("Face mismatch" if dist > 10 else "Outside geofence"),
            metadata={"distance": dist},
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        create_document("attendance", att)
        raise HTTPException(status_code=400, detail="Face mismatch or outside geofence")

@app.post("/attendance/mark/qr")
def mark_attendance_qr(req: QRMarkRequest, auth=Depends(require_auth)):
    payload = decode_token(req.qr_token)
    t = payload.get("type")
    inside = check_geofence(req.lat, req.lng)
    if not inside:
        att = AttendanceSchema(
            user_id=auth["sub"], method='qr_self' if t=='qr_self' else 'qr_session',
            lat=req.lat, lng=req.lng, inside_geofence=False, status='rejected',
            reason='Outside geofence', metadata={"token": t},
            created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc)
        )
        create_document("attendance", att)
        raise HTTPException(status_code=400, detail="Outside geofence")

    if t == 'qr_self':
        if payload.get("sub") != auth["sub"]:
            raise HTTPException(status_code=400, detail="QR does not belong to this user")
        att = AttendanceSchema(
            user_id=auth["sub"], method='qr_self', lat=req.lat, lng=req.lng, inside_geofence=True,
            status='present', reason=None, metadata=None,
            created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc)
        )
        att_id = create_document("attendance", att)
        return {"status": "marked", "attendance_id": att_id, "method": "qr_self"}
    elif t == 'qr_session':
        sid = payload.get("sid")
        tid = payload.get("tid")
        s = db["session"].find_one({"_id": to_object_id(sid), "token_id": tid, "active": True})
        if not s:
            raise HTTPException(status_code=400, detail="Invalid session")
        att = AttendanceSchema(
            user_id=auth["sub"], method='qr_session', lat=req.lat, lng=req.lng, inside_geofence=True,
            status='present', reason=None, metadata={"session_id": sid},
            created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc)
        )
        att_id = create_document("attendance", att)
        return {"status": "marked", "attendance_id": att_id, "method": "qr_session"}
    else:
        raise HTTPException(status_code=400, detail="Unsupported QR token")

# ---------------------- History & Reports ----------------------
@app.get("/attendance/history")
def history(auth=Depends(require_auth)):
    docs = get_documents("attendance", {"user_id": auth["sub"]}, limit=None)
    for d in docs:
        d["_id"] = str(d["_id"]) if d.get("_id") else None
    docs.sort(key=lambda x: x.get("created_at", datetime.min), reverse=True)
    return {"items": docs}

@app.get("/admin/registrations")
def pending_registrations(auth=Depends(require_auth)):
    if auth.get("role") not in ["faculty", "admin"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    users = list(db["user"].find({"approved": False}, {"password_hash": 0, "face_encrypted": 0}))
    for u in users:
        u["_id"] = str(u["_id"]) if u.get("_id") else None
    return {"items": users}

@app.patch("/admin/users/{user_id}/approve")
def approve_user(user_id: str, approve: bool = Query(True), auth=Depends(require_auth)):
    if auth.get("role") not in ["faculty", "admin"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    res = db["user"].update_one({"_id": to_object_id(user_id)}, {"$set": {"approved": approve, "updated_at": datetime.now(timezone.utc)}})
    return {"matched": res.matched_count, "modified": res.modified_count}

@app.get("/admin/reports")
def admin_reports(
    department: Optional[str] = None,
    class_section: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
    auth=Depends(require_auth)
):
    if auth.get("role") not in ["faculty", "admin"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    start_dt = datetime.fromisoformat(start) if start else datetime.now(timezone.utc) - timedelta(days=30)
    end_dt = datetime.fromisoformat(end) if end else datetime.now(timezone.utc)
    atts = list(db["attendance"].find({
        "created_at": {"$gte": start_dt, "$lte": end_dt},
        "status": "present"
    }))
    user_ids = list({a.get("user_id") for a in atts if a.get("user_id")})
    users = {str(u["_id"]): u for u in db["user"].find({"_id": {"$in": [to_object_id(uid) for uid in user_ids]}})}
    filtered = []
    for a in atts:
        u = users.get(a.get("user_id"))
        if not u:
            continue
        if department and u.get("department") != department:
            continue
        if class_section and u.get("class_section") != class_section:
            continue
        filtered.append(a)
    total = len(filtered)
    by_method = {}
    for a in filtered:
        m = a.get("method", "unknown")
        by_method[m] = by_method.get(m, 0) + 1
    return {"total": total, "by_method": by_method}

# ---------------------- Privacy ----------------------
@app.delete("/me/face")
def delete_face(auth=Depends(require_auth)):
    db["user"].update_one({"_id": to_object_id(auth["sub"])}, {"$unset": {"face_encrypted": "", "face_phash": ""}, "$set": {"updated_at": datetime.now(timezone.utc)}})
    return {"status": "face-data-deleted"}
