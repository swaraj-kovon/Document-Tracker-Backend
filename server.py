from dotenv import load_dotenv

load_dotenv()

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import jwt
import resend
from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    File,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, EmailStr
from supabase import Client, create_client

# ── Setup ──────────────────────────────────────────────────────────────────
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_KEY = os.environ["SUPABASE_SERVICE_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

resend.api_key = os.environ.get("RESEND_API_KEY")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL")
BACKEND_URL = os.environ.get("BACKEND_URL")
FRONTEND_URL = os.environ.get("FRONTEND_URL")
SUPABASE_JWT_SECRET = os.environ.get("SUPABASE_JWT_SECRET", "")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "founders@kovon.io")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "KovonAdmin@2026")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Categories ─────────────────────────────────────────────────────────────
CATEGORIES = {
    "HR": {
        "name": "Human Resources",
        "code": "HR",
        "types": [
            "Employment Offer Letter",
            "Internship Offer Letter",
            "Experience Letter",
            "Joining Letter",
            "Relieving Letter",
            "Promotion Letter",
            "Warning Letter",
        ],
    },
    "LG": {
        "name": "Legal",
        "code": "LG",
        "types": ["Contracts", "Agreements", "NDAs", "Compliance Letters"],
    },
    "FN": {
        "name": "Finance",
        "code": "FN",
        "types": ["Invoice Approval", "Expense Approval", "Salary Letters"],
    },
    "BR": {"name": "Board", "code": "BR", "types": ["Board Resolutions"]},
    "SH": {
        "name": "Shareholder",
        "code": "SH",
        "types": ["Shareholder Meeting Notice", "Voting Resolution"],
    },
    "OP": {
        "name": "Operations",
        "code": "OP",
        "types": ["Vendor Agreements", "Internal Memos"],
    },
    "OT": {"name": "Others", "code": "OT", "types": ["Miscellaneous Documents"]},
}

# ── FastAPI App ─────────────────────────────────────────────────────────────
app = FastAPI()
api_router = APIRouter(prefix="/api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Supabase Helpers ───────────────────────────────────────────────────────
async def _sb(fn):
    """Run a synchronous supabase call off the event loop."""
    return await asyncio.to_thread(fn)


def _norm(row: dict) -> dict:
    """Add _id alias for React frontend compatibility."""
    if row and "id" in row:
        row["_id"] = row["id"]
    return row


def _norm_list(rows) -> list:
    return [_norm(r) for r in (rows or [])]


# ── Auth Utilities ─────────────────────────────────────────────────────────
async def get_current_user(request: Request) -> dict:
    token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(
            token,
            SUPABASE_JWT_SECRET,
            algorithms=["HS256"],
            options={"verify_aud": False},  # Supabase uses "authenticated"
        )
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        r = await _sb(
            lambda: supabase.table("profiles").select("*").eq("id", user_id).execute()
        )
        if not r.data:
            raise HTTPException(status_code=401, detail="User not found")
        user = r.data[0]
        user["_id"] = user["id"]
        if user.get("is_blocked", False):
            raise HTTPException(
                status_code=403,
                detail="Your account has been blocked. Please contact the administrator.",
            )
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_admin_user(request: Request) -> dict:
    user = await get_current_user(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# ── Email ──────────────────────────────────────────────────────────────────
async def send_email(to: str, subject: str, html: str):
    api_key = os.environ.get("RESEND_API_KEY", "").strip()
    if not api_key:
        logger.warning(
            f"RESEND_API_KEY is not set — skipping email to {to} | subject: {subject}"
        )
        return

    resend.api_key = api_key

    params: resend.Emails.SendParams = {
        "from": SENDER_EMAIL,
        "to": [to],
        "subject": subject,
        "html": html,
    }

    try:
        result = await resend.Emails.send_async(params)
        logger.info(f"Email sent OK → {to} | id: {result.id}")
    except Exception as e:
        logger.error(
            f"Email FAILED → {to} | subject: {subject} | "
            f"sender: {SENDER_EMAIL} | error: {type(e).__name__}: {e}"
        )


def build_approval_email(doc: dict, approve_url: str, reject_url: str) -> str:
    file_section = (
        f"<p><a href='{doc.get('file_url', '#')}' style='color:#1B2A4A;font-size:14px;'>View Document File</a></p>"
        if doc.get("file_url")
        else ""
    )
    return f"""<!DOCTYPE html><html><body style="font-family:'Segoe UI',Arial,sans-serif;background:#f8fafc;padding:40px;margin:0;">
    <div style="max-width:600px;margin:0 auto;background:white;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1);">
        <div style="background:#1B2A4A;padding:24px 32px;"><h1 style="color:white;margin:0;font-size:20px;">Document Approval Request</h1>
        <p style="color:#94a3b8;margin:4px 0 0;font-size:14px;">Kovon Document Registry</p></div>
        <div style="padding:32px;">
        <table style="width:100%;border-collapse:collapse;margin-bottom:24px;">
            <tr style="border-bottom:1px solid #e2e8f0;"><td style="padding:10px 0;color:#64748b;font-size:13px;width:40%;">Serial Number</td><td style="padding:10px 0;color:#0f172a;font-weight:600;font-size:13px;">{doc.get("serial_number", "N/A")}</td></tr>
            <tr style="border-bottom:1px solid #e2e8f0;"><td style="padding:10px 0;color:#64748b;font-size:13px;">Title</td><td style="padding:10px 0;color:#0f172a;font-size:13px;">{doc.get("title", "N/A")}</td></tr>
            <tr style="border-bottom:1px solid #e2e8f0;"><td style="padding:10px 0;color:#64748b;font-size:13px;">Category</td><td style="padding:10px 0;color:#0f172a;font-size:13px;">{doc.get("category", "N/A")}</td></tr>
            <tr style="border-bottom:1px solid #e2e8f0;"><td style="padding:10px 0;color:#64748b;font-size:13px;">Document Type</td><td style="padding:10px 0;color:#0f172a;font-size:13px;">{doc.get("document_type", "N/A")}</td></tr>
            <tr style="border-bottom:1px solid #e2e8f0;"><td style="padding:10px 0;color:#64748b;font-size:13px;">To</td><td style="padding:10px 0;color:#0f172a;font-size:13px;">{doc.get("to_field", "N/A")}</td></tr>
            <tr style="border-bottom:1px solid #e2e8f0;"><td style="padding:10px 0;color:#64748b;font-size:13px;">Generated By</td><td style="padding:10px 0;color:#0f172a;font-size:13px;">{doc.get("generated_by", "N/A")}</td></tr>
            <tr><td style="padding:10px 0;color:#64748b;font-size:13px;">Description</td><td style="padding:10px 0;color:#0f172a;font-size:13px;">{doc.get("description", "N/A")}</td></tr>
        </table>
        {file_section}
        <div style="margin-top:24px;">
            <a href="{approve_url}" style="display:inline-block;background:#22c55e;color:white;padding:12px 32px;border-radius:6px;text-decoration:none;font-weight:600;font-size:14px;">Approve</a>
            <a href="{reject_url}" style="display:inline-block;background:#ef4444;color:white;padding:12px 32px;border-radius:6px;text-decoration:none;font-weight:600;font-size:14px;margin-left:16px;">Reject</a>
        </div></div></div></body></html>"""


def build_verification_email(verify_url: str) -> str:
    return f"""<!DOCTYPE html><html><body style="font-family:'Segoe UI',Arial,sans-serif;background:#f8fafc;padding:40px;margin:0;">
    <div style="max-width:600px;margin:0 auto;background:white;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1);">
        <div style="background:#1B2A4A;padding:24px 32px;"><h1 style="color:white;margin:0;font-size:20px;">Verify Your Email</h1>
        <p style="color:#94a3b8;margin:4px 0 0;font-size:14px;">Kovon Document Registry</p></div>
        <div style="padding:32px;">
        <p style="color:#475569;font-size:14px;margin-bottom:24px;">Please verify your email address to activate your Kovon Document Registry account.</p>
        <a href="{verify_url}" style="display:inline-block;background:#1B2A4A;color:white;padding:12px 32px;border-radius:6px;text-decoration:none;font-weight:600;font-size:14px;">Verify Email Address</a>
        <p style="color:#94a3b8;font-size:12px;margin-top:24px;">This link expires in 24 hours. If you didn't create this account, please ignore this email.</p>
        </div></div></body></html>"""


def build_reset_email(reset_url: str) -> str:
    return f"""<!DOCTYPE html><html><body style="font-family:'Segoe UI',Arial,sans-serif;background:#f8fafc;padding:40px;margin:0;">
    <div style="max-width:600px;margin:0 auto;background:white;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1);">
        <div style="background:#1B2A4A;padding:24px 32px;"><h1 style="color:white;margin:0;font-size:20px;">Reset Your Password</h1>
        <p style="color:#94a3b8;margin:4px 0 0;font-size:14px;">Kovon Document Registry</p></div>
        <div style="padding:32px;">
        <p style="color:#475569;font-size:14px;margin-bottom:24px;">We received a request to reset your password. Click below to set a new password.</p>
        <a href="{reset_url}" style="display:inline-block;background:#1B2A4A;color:white;padding:12px 32px;border-radius:6px;text-decoration:none;font-weight:600;font-size:14px;">Reset Password</a>
        <p style="color:#94a3b8;font-size:12px;margin-top:24px;">This link expires in 1 hour. If you didn't request this, ignore this email.</p>
        </div></div></body></html>"""


def build_status_email(doc: dict, status: str, remarks: str = "") -> str:
    color = "#22c55e" if status == "approved" else "#ef4444"
    status_text = "Approved" if status == "approved" else "Rejected"
    return f"""<!DOCTYPE html><html><body style="font-family:'Segoe UI',Arial,sans-serif;background:#f8fafc;padding:40px;margin:0;">
    <div style="max-width:600px;margin:0 auto;background:white;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1);">
        <div style="background:#1B2A4A;padding:24px 32px;"><h1 style="color:white;margin:0;font-size:20px;">Document {status_text}</h1></div>
        <div style="padding:32px;"><p style="color:#0f172a;font-size:15px;">Your document <strong>{doc.get("serial_number", "")}</strong> — <em>{doc.get("title", "")}</em> has been <span style="color:{color};font-weight:600;">{status_text}</span>.</p>
        {"<p style='color:#64748b;font-size:14px;'><strong>Remarks:</strong> " + remarks + "</p>" if remarks else ""}
        <a href="{FRONTEND_URL}/documents/{doc.get("_id", "")}" style="display:inline-block;background:#1B2A4A;color:white;padding:10px 24px;border-radius:6px;text-decoration:none;font-weight:600;font-size:14px;margin-top:16px;">View Document</a>
        </div></div></body></html>"""


# ── Pydantic Models ────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class CreateDocumentRequest(BaseModel):
    category: str
    category_code: str
    document_type: str
    title: str
    to_field: str
    description: Optional[str] = ""


class UpdateDocumentRequest(BaseModel):
    title: str
    to_field: str
    description: Optional[str] = ""


class RejectRequest(BaseModel):
    remarks: str = ""


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


# ── Auth Routes ────────────────────────────────────────────────────────────
@api_router.post("/auth/register")
async def register(req: RegisterRequest):
    email = req.email.lower().strip()
    if not email.endswith("@kovon.io"):
        raise HTTPException(
            status_code=400,
            detail="Only @kovon.io email addresses are allowed to register",
        )
    try:
        result = await asyncio.to_thread(
            supabase.auth.sign_up,
            {
                "email": email,
                "password": req.password,
                "options": {
                    "data": {"name": req.name},
                    "email_redirect_to": f"{FRONTEND_URL}/login?verified=true",
                },
            },
        )
    except Exception as e:
        msg = str(e).lower()
        if "already registered" in msg or "already been registered" in msg:
            raise HTTPException(status_code=400, detail="Email already registered")
        raise HTTPException(status_code=400, detail=f"Registration failed: {e}")

    if not result.user:
        raise HTTPException(status_code=400, detail="Registration failed")

    # If admin email, promote role immediately
    if email == ADMIN_EMAIL:
        uid = str(result.user.id)
        await _sb(
            lambda: (
                supabase.auth.admin.update_user_by_id(uid, {"user_metadata": {"role": "admin"}})
                .execute()
            )
        )

    return {
        "message": "Registration successful. Please check your email to verify your account.",
        "needs_verification": True,
    }


@api_router.post("/auth/login")
async def login(req: LoginRequest):
    email = req.email.lower().strip()
    if not email.endswith("@kovon.io"):
        raise HTTPException(
            status_code=400, detail="Only @kovon.io email addresses are allowed"
        )
    try:
        result = await asyncio.to_thread(
            supabase.auth.sign_in_with_password,
            {"email": email, "password": req.password},
        )
    except Exception as e:
        msg = str(e).lower()
        if "email not confirmed" in msg:
            raise HTTPException(status_code=403, detail="EMAIL_NOT_VERIFIED")
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not result.user or not result.session:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    user_id = str(result.user.id)
    r = await _sb(
        lambda: supabase.table("profiles").select("*").eq("id", user_id).execute()
    )
    if not r.data:
        raise HTTPException(status_code=401, detail="User profile not found")

    profile = r.data[0]
    if profile.get("is_blocked", False):
        raise HTTPException(
            status_code=403,
            detail="Your account has been blocked. Please contact the administrator.",
        )

    return {
        "token": result.session.access_token,
        "user": {
            "id": user_id,
            "email": email,
            "name": profile.get("name", ""),
            "role": profile.get("role", "user"),
        },
    }


@api_router.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return user


# ── Forgot / Reset Password ───────────────────────────────────────────────
@api_router.post("/auth/forgot-password")
async def forgot_password(req: ForgotPasswordRequest):
    email = req.email.lower().strip()
    try:
        await asyncio.to_thread(
            supabase.auth.reset_password_for_email,
            email,
            {"redirect_to": f"{FRONTEND_URL}/reset-password"},
        )
    except Exception:
        pass  # Never reveal whether email exists
    return {
        "message": "If that email is registered, a password reset link has been sent."
    }


@api_router.post("/auth/reset-password")
async def reset_password(req: ResetPasswordRequest):
    if len(req.new_password) < 6:
        raise HTTPException(
            status_code=400, detail="Password must be at least 6 characters"
        )
    try:
        payload = jwt.decode(
            req.token,
            SUPABASE_JWT_SECRET,
            algorithms=["HS256"],
            options={"verify_aud": False},
        )
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid reset token")
        await asyncio.to_thread(
            supabase.auth.admin.update_user_by_id,
            user_id,
            {"password": req.new_password},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=400, detail="Reset link has expired. Please request a new one."
        )
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid or expired reset link")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Password reset failed: {e}")
    return {
        "message": "Password reset successfully. You can now sign in with your new password."
    }


@api_router.post("/auth/change-password")
async def change_password(
    req: ChangePasswordRequest, user: dict = Depends(get_current_user)
):
    email = user["email"]
    # Verify current password by attempting sign-in
    try:
        await asyncio.to_thread(
            supabase.auth.sign_in_with_password,
            {"email": email, "password": req.current_password},
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(req.new_password) < 6:
        raise HTTPException(
            status_code=400, detail="New password must be at least 6 characters"
        )
    try:
        await asyncio.to_thread(
            supabase.auth.admin.update_user_by_id,
            user["id"],
            {"password": req.new_password},
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to update password: {e}")
    return {"message": "Password changed successfully"}


# ── Categories ─────────────────────────────────────────────────────────────
@api_router.get("/categories")
async def get_categories():
    return CATEGORIES


# ── Dashboard ──────────────────────────────────────────────────────────────
@api_router.get("/dashboard/stats")
async def dashboard_stats(user: dict = Depends(get_current_user)):
    is_admin = user["role"] == "admin"
    uid = user["id"]

    if is_admin:
        r_total = await _sb(
            lambda: supabase.table("documents").select("id", count="exact").execute()
        )
        total = r_total.count or 0

        r_pending = await _sb(
            lambda: (
                supabase.table("documents")
                .select("id", count="exact")
                .eq("status", "pending")
                .execute()
            )
        )
        pending = r_pending.count or 0

        r_approved = await _sb(
            lambda: (
                supabase.table("documents")
                .select("id", count="exact")
                .eq("status", "approved")
                .execute()
            )
        )
        approved = r_approved.count or 0

        r_rejected = await _sb(
            lambda: (
                supabase.table("documents")
                .select("id", count="exact")
                .eq("status", "rejected")
                .execute()
            )
        )
        rejected = r_rejected.count or 0

        r_draft = await _sb(
            lambda: (
                supabase.table("documents")
                .select("id", count="exact")
                .eq("status", "draft")
                .execute()
            )
        )
        draft = r_draft.count or 0

        r_recent = await _sb(
            lambda: (
                supabase.table("documents")
                .select("id,serial_number,title,status,created_at,category")
                .order("created_at", desc=True)
                .limit(5)
                .execute()
            )
        )
    else:
        r_total = await _sb(
            lambda: (
                supabase.table("documents")
                .select("id", count="exact")
                .eq("generated_by_user_id", uid)
                .execute()
            )
        )
        total = r_total.count or 0

        r_pending = await _sb(
            lambda: (
                supabase.table("documents")
                .select("id", count="exact")
                .eq("generated_by_user_id", uid)
                .eq("status", "pending")
                .execute()
            )
        )
        pending = r_pending.count or 0

        r_approved = await _sb(
            lambda: (
                supabase.table("documents")
                .select("id", count="exact")
                .eq("generated_by_user_id", uid)
                .eq("status", "approved")
                .execute()
            )
        )
        approved = r_approved.count or 0

        r_rejected = await _sb(
            lambda: (
                supabase.table("documents")
                .select("id", count="exact")
                .eq("generated_by_user_id", uid)
                .eq("status", "rejected")
                .execute()
            )
        )
        rejected = r_rejected.count or 0

        r_draft = await _sb(
            lambda: (
                supabase.table("documents")
                .select("id", count="exact")
                .eq("generated_by_user_id", uid)
                .eq("status", "draft")
                .execute()
            )
        )
        draft = r_draft.count or 0

        r_recent = await _sb(
            lambda: (
                supabase.table("documents")
                .select("id,serial_number,title,status,created_at,category")
                .eq("generated_by_user_id", uid)
                .order("created_at", desc=True)
                .limit(5)
                .execute()
            )
        )

    recent = _norm_list(r_recent.data)
    return {
        "total": total,
        "pending": pending,
        "approved": approved,
        "rejected": rejected,
        "draft": draft,
        "recent": recent,
    }


# ── Documents ──────────────────────────────────────────────────────────────
@api_router.get("/documents")
async def list_documents(user: dict = Depends(get_current_user)):
    uid = user["id"]
    r = await _sb(
        lambda: (
            supabase.table("documents")
            .select("*")
            .eq("generated_by_user_id", uid)
            .order("created_at", desc=True)
            .execute()
        )
    )
    return _norm_list(r.data)


@api_router.post("/documents")
async def create_document(
    req: CreateDocumentRequest, user: dict = Depends(get_current_user)
):
    now = datetime.now(timezone.utc)
    year = now.year
    code = req.category_code

    r = await _sb(
        lambda: supabase.rpc(
            "increment_serial_counter", {"p_category_code": code, "p_year": year}
        ).execute()
    )
    counter = r.data
    serial_number = f"KGPL/{code}/{year}/{str(counter).zfill(4)}"

    doc = {
        "serial_number": serial_number,
        "category": req.category,
        "category_code": code,
        "document_type": req.document_type,
        "title": req.title,
        "to_field": req.to_field,
        "generated_by": user["email"],
        "generated_by_user_id": user["id"],
        "description": req.description or "",
        "file_url": None,
        "file_name": None,
        "file_path": None,
        "status": "draft",
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "year": year,
        "serial_counter": counter,
    }
    r = await _sb(lambda: supabase.table("documents").insert(doc).execute())
    if not r.data:
        raise HTTPException(status_code=500, detail="Failed to create document")
    created = _norm(r.data[0])

    audit = {
        "document_id": created["id"],
        "action": "created",
        "action_by": user["email"],
        "timestamp": now.isoformat(),
        "details": f"Document created with serial {serial_number}",
    }
    await _sb(lambda: supabase.table("audit_logs").insert(audit).execute())
    return created


@api_router.get("/documents/{doc_id}")
async def get_document(doc_id: str, user: dict = Depends(get_current_user)):
    r = await _sb(
        lambda: supabase.table("documents").select("*").eq("id", doc_id).execute()
    )
    if not r.data:
        raise HTTPException(status_code=404, detail="Document not found")
    doc = _norm(r.data[0])
    if user["role"] != "admin" and doc.get("generated_by_user_id") != user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    r_logs = await _sb(
        lambda: (
            supabase.table("audit_logs")
            .select("*")
            .eq("document_id", doc_id)
            .order("timestamp", desc=False)
            .execute()
        )
    )
    doc["audit_logs"] = _norm_list(r_logs.data)
    return doc


@api_router.put("/documents/{doc_id}")
async def update_document(
    doc_id: str, req: UpdateDocumentRequest, user: dict = Depends(get_current_user)
):
    r = await _sb(
        lambda: supabase.table("documents").select("*").eq("id", doc_id).execute()
    )
    if not r.data:
        raise HTTPException(status_code=404, detail="Document not found")
    doc = r.data[0]
    if user["role"] != "admin" and doc.get("generated_by_user_id") != user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    if doc["status"] == "approved":
        raise HTTPException(
            status_code=403, detail="Approved documents cannot be modified"
        )
    now = datetime.now(timezone.utc)
    updates = {
        "title": req.title,
        "to_field": req.to_field,
        "description": req.description,
        "updated_at": now.isoformat(),
    }
    await _sb(
        lambda: supabase.table("documents").update(updates).eq("id", doc_id).execute()
    )
    r2 = await _sb(
        lambda: supabase.table("documents").select("*").eq("id", doc_id).execute()
    )
    return _norm(r2.data[0])


@api_router.post("/documents/{doc_id}/upload")
async def upload_file(
    doc_id: str, file: UploadFile = File(...), user: dict = Depends(get_current_user)
):
    r = await _sb(
        lambda: supabase.table("documents").select("*").eq("id", doc_id).execute()
    )
    if not r.data:
        raise HTTPException(status_code=404, detail="Document not found")
    doc = r.data[0]
    if user["role"] != "admin" and doc.get("generated_by_user_id") != user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    if doc["status"] == "approved":
        raise HTTPException(
            status_code=403, detail="Approved documents cannot be modified"
        )

    ext = Path(file.filename).suffix.lower()
    if ext not in [".pdf", ".docx"]:
        raise HTTPException(
            status_code=400, detail="Only PDF and DOCX files are allowed"
        )

    if ext == ".pdf":
        mime = "application/pdf"
    else:
        mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

    serial_safe = doc["serial_number"].replace("/", "-")
    storage_path = f"{serial_safe}_{file.filename}"
    content = await file.read()

    def _upload():
        return supabase.storage.from_("documents").upload(
            storage_path,
            content,
            {"content-type": mime, "upsert": "true"},
        )

    try:
        await _sb(_upload)
    except Exception as e:
        logger.error(f"Storage upload error: {e}")
        raise HTTPException(status_code=500, detail=f"File upload failed: {e}")

    file_url = supabase.storage.from_("documents").get_public_url(storage_path)
    now = datetime.now(timezone.utc)

    doc_updates = {
        "file_url": file_url,
        "file_name": file.filename,
        "file_path": storage_path,
        "updated_at": now.isoformat(),
    }
    await _sb(
        lambda: (
            supabase.table("documents").update(doc_updates).eq("id", doc_id).execute()
        )
    )

    audit = {
        "document_id": doc_id,
        "action": "file_uploaded",
        "action_by": user["email"],
        "timestamp": now.isoformat(),
        "details": f"File uploaded: {file.filename}",
    }
    await _sb(lambda: supabase.table("audit_logs").insert(audit).execute())

    r2 = await _sb(
        lambda: supabase.table("documents").select("*").eq("id", doc_id).execute()
    )
    return _norm(r2.data[0])


@api_router.post("/documents/{doc_id}/submit")
async def submit_document(doc_id: str, user: dict = Depends(get_current_user)):
    r = await _sb(
        lambda: supabase.table("documents").select("*").eq("id", doc_id).execute()
    )
    if not r.data:
        raise HTTPException(status_code=404, detail="Document not found")
    doc = r.data[0]
    if user["role"] != "admin" and doc.get("generated_by_user_id") != user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    if doc["status"] == "approved":
        raise HTTPException(
            status_code=403, detail="Approved documents cannot be re-submitted"
        )
    if doc["status"] == "pending":
        raise HTTPException(
            status_code=400, detail="Document is already pending approval"
        )

    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)

    approval_token_doc = {
        "token": token,
        "document_id": doc_id,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(days=7)).isoformat(),
        "used": False,
    }
    await _sb(
        lambda: supabase.table("approval_tokens").insert(approval_token_doc).execute()
    )
    await _sb(
        lambda: (
            supabase.table("documents")
            .update({"status": "pending", "updated_at": now.isoformat()})
            .eq("id", doc_id)
            .execute()
        )
    )

    audit = {
        "document_id": doc_id,
        "action": "submitted",
        "action_by": user["email"],
        "timestamp": now.isoformat(),
        "details": "Document submitted for approval",
    }
    await _sb(lambda: supabase.table("audit_logs").insert(audit).execute())

    doc = _norm(doc)
    approve_url = f"{BACKEND_URL}/api/approvals/approve/{token}"
    reject_url = f"{BACKEND_URL}/api/approvals/reject/{token}"
    email_html = build_approval_email(doc, approve_url, reject_url)
    await send_email(
        to=ADMIN_EMAIL,
        subject=f"Approval Required: {doc['serial_number']} - {doc['title']}",
        html=email_html,
    )

    r2 = await _sb(
        lambda: supabase.table("documents").select("*").eq("id", doc_id).execute()
    )
    return _norm(r2.data[0])


# ── Admin Routes ───────────────────────────────────────────────────────────
@api_router.get("/admin/documents")
async def admin_list_documents(
    status: Optional[str] = None,
    category_code: Optional[str] = None,
    user_email: Optional[str] = None,
    user: dict = Depends(get_admin_user),
):
    q = supabase.table("documents").select("*")
    if status:
        q = q.eq("status", status)
    if category_code:
        q = q.eq("category_code", category_code)
    if user_email:
        q = q.eq("generated_by", user_email)
    q = q.order("created_at", desc=True)
    r = await _sb(lambda q=q: q.execute())
    return _norm_list(r.data)


@api_router.get("/admin/users")
async def admin_list_users(user: dict = Depends(get_admin_user)):
    r = await _sb(
        lambda: (
            supabase.table("profiles")
            .select("id,email,name,role,created_at,is_blocked")
            .execute()
        )
    )
    return _norm_list(r.data)


@api_router.post("/admin/documents/{doc_id}/approve")
async def admin_approve(doc_id: str, user: dict = Depends(get_admin_user)):
    r = await _sb(
        lambda: supabase.table("documents").select("*").eq("id", doc_id).execute()
    )
    if not r.data:
        raise HTTPException(status_code=404, detail="Document not found")
    doc = r.data[0]
    if doc["status"] == "approved":
        raise HTTPException(status_code=400, detail="Document is already approved")
    now = datetime.now(timezone.utc)
    await _sb(
        lambda: (
            supabase.table("documents")
            .update({"status": "approved", "updated_at": now.isoformat()})
            .eq("id", doc_id)
            .execute()
        )
    )
    approval = {
        "document_id": doc_id,
        "status": "approved",
        "action_by": user["email"],
        "action_date": now.isoformat(),
        "remarks": "",
    }
    await _sb(lambda: supabase.table("approvals").insert(approval).execute())
    audit = {
        "document_id": doc_id,
        "action": "approved",
        "action_by": user["email"],
        "timestamp": now.isoformat(),
        "details": "Approved by admin",
    }
    await _sb(lambda: supabase.table("audit_logs").insert(audit).execute())
    doc = _norm(doc)
    submitter = doc.get("generated_by", "")
    if submitter:
        await send_email(
            to=submitter,
            subject=f"Document Approved: {doc['serial_number']}",
            html=build_status_email(doc, "approved"),
        )
    r2 = await _sb(
        lambda: supabase.table("documents").select("*").eq("id", doc_id).execute()
    )
    return _norm(r2.data[0])


@api_router.post("/admin/documents/{doc_id}/reject")
async def admin_reject(
    doc_id: str, req: RejectRequest, user: dict = Depends(get_admin_user)
):
    r = await _sb(
        lambda: supabase.table("documents").select("*").eq("id", doc_id).execute()
    )
    if not r.data:
        raise HTTPException(status_code=404, detail="Document not found")
    doc = r.data[0]
    if doc["status"] == "approved":
        raise HTTPException(
            status_code=400, detail="Approved documents cannot be rejected"
        )
    now = datetime.now(timezone.utc)
    await _sb(
        lambda: (
            supabase.table("documents")
            .update({"status": "rejected", "updated_at": now.isoformat()})
            .eq("id", doc_id)
            .execute()
        )
    )
    approval = {
        "document_id": doc_id,
        "status": "rejected",
        "action_by": user["email"],
        "action_date": now.isoformat(),
        "remarks": req.remarks,
    }
    await _sb(lambda: supabase.table("approvals").insert(approval).execute())
    details = (
        f"Rejected by admin. Remarks: {req.remarks}"
        if req.remarks
        else "Rejected by admin"
    )
    audit = {
        "document_id": doc_id,
        "action": "rejected",
        "action_by": user["email"],
        "timestamp": now.isoformat(),
        "details": details,
    }
    await _sb(lambda: supabase.table("audit_logs").insert(audit).execute())
    doc = _norm(doc)
    submitter = doc.get("generated_by", "")
    if submitter:
        await send_email(
            to=submitter,
            subject=f"Document Rejected: {doc['serial_number']}",
            html=build_status_email(doc, "rejected", req.remarks),
        )
    r2 = await _sb(
        lambda: supabase.table("documents").select("*").eq("id", doc_id).execute()
    )
    return _norm(r2.data[0])


@api_router.get("/admin/audit-log")
async def admin_audit_log(
    document_id: Optional[str] = None, user: dict = Depends(get_admin_user)
):
    q = supabase.table("audit_logs").select("*")
    if document_id:
        q = q.eq("document_id", document_id)
    q = q.order("timestamp", desc=True)
    r = await _sb(lambda q=q: q.execute())
    return _norm_list(r.data)


# ── Admin Block / Unblock ─────────────────────────────────────────────────
@api_router.post("/admin/users/{user_id}/block")
async def admin_block_user(user_id: str, user: dict = Depends(get_admin_user)):
    r = await _sb(
        lambda: supabase.table("profiles").select("id,email").eq("id", user_id).execute()
    )
    if not r.data:
        raise HTTPException(status_code=404, detail="User not found")
    target = r.data[0]
    if target.get("email") == ADMIN_EMAIL:
        raise HTTPException(status_code=400, detail="Cannot block the admin account")
    await _sb(
        lambda: (
            supabase.table("profiles")
            .update({"is_blocked": True})
            .eq("id", user_id)
            .execute()
        )
    )
    return {"message": "User blocked successfully"}


@api_router.post("/admin/users/{user_id}/unblock")
async def admin_unblock_user(user_id: str, user: dict = Depends(get_admin_user)):
    r = await _sb(
        lambda: supabase.table("profiles").select("id").eq("id", user_id).execute()
    )
    if not r.data:
        raise HTTPException(status_code=404, detail="User not found")
    await _sb(
        lambda: (
            supabase.table("profiles")
            .update({"is_blocked": False})
            .eq("id", user_id)
            .execute()
        )
    )
    return {"message": "User unblocked successfully"}


# ── Approval Email Endpoints ───────────────────────────────────────────────
def _html_page(
    title: str,
    color: str,
    icon: str,
    heading: str,
    body: str,
    serial: str = "",
    doc_title: str = "",
) -> str:
    return f"""<!DOCTYPE html><html><head><title>{title}</title></head>
    <body style="font-family:'Segoe UI',sans-serif;background:#f8fafc;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">
    <div style="background:white;padding:48px;border-radius:12px;box-shadow:0 4px 16px rgba(0,0,0,0.1);text-align:center;max-width:480px;">
        <div style="background:{color}20;border-radius:50%;width:64px;height:64px;display:flex;align-items:center;justify-content:center;margin:0 auto 24px;font-size:32px;">{icon}</div>
        <h2 style="color:{color};margin:0 0 8px;">{heading}</h2>
        {f'<p style="color:#475569;margin:0 0 4px;font-weight:600;">{serial}</p>' if serial else ""}
        {f'<p style="color:#64748b;margin:0 0 24px;">{doc_title}</p>' if doc_title else ""}
        <p style="color:#64748b;margin:0 0 24px;">{body}</p>
        <a href="{FRONTEND_URL}" style="background:#1B2A4A;color:white;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;">Go to Registry</a>
    </div></body></html>"""


@api_router.get("/approvals/approve/{token}", response_class=HTMLResponse)
async def approve_from_email(token: str):
    r = await _sb(
        lambda: (
            supabase.table("approval_tokens").select("*").eq("token", token).execute()
        )
    )
    if not r.data:
        return HTMLResponse(
            _html_page(
                "Invalid",
                "#ef4444",
                "✗",
                "Invalid Link",
                "This approval link is invalid or has expired.",
            ),
            status_code=400,
        )
    token_doc = r.data[0]
    if token_doc.get("used"):
        return HTMLResponse(
            _html_page(
                "Used",
                "#f59e0b",
                "!",
                "Already Processed",
                "This approval link has already been used.",
            )
        )
    doc_id = token_doc["document_id"]
    r2 = await _sb(
        lambda: supabase.table("documents").select("*").eq("id", doc_id).execute()
    )
    if not r2.data:
        return HTMLResponse(
            _html_page("Error", "#ef4444", "✗", "Error", "Document not found."),
            status_code=404,
        )
    doc = r2.data[0]
    if doc["status"] == "approved":
        doc = _norm(doc)
        return HTMLResponse(
            _html_page(
                "Approved",
                "#22c55e",
                "✓",
                "Already Approved",
                "This document is already approved.",
                doc["serial_number"],
                doc["title"],
            )
        )
    now = datetime.now(timezone.utc)
    await _sb(
        lambda: (
            supabase.table("documents")
            .update({"status": "approved", "updated_at": now.isoformat()})
            .eq("id", doc_id)
            .execute()
        )
    )
    await _sb(
        lambda: (
            supabase.table("approval_tokens")
            .update({"used": True})
            .eq("token", token)
            .execute()
        )
    )
    approval = {
        "document_id": doc_id,
        "status": "approved",
        "action_by": ADMIN_EMAIL,
        "action_date": now.isoformat(),
        "remarks": "Approved via email",
    }
    await _sb(lambda: supabase.table("approvals").insert(approval).execute())
    audit = {
        "document_id": doc_id,
        "action": "approved",
        "action_by": ADMIN_EMAIL,
        "timestamp": now.isoformat(),
        "details": "Approved via email link",
    }
    await _sb(lambda: supabase.table("audit_logs").insert(audit).execute())
    doc = _norm(doc)
    submitter = doc.get("generated_by", "")
    if submitter:
        await send_email(
            to=submitter,
            subject=f"Document Approved: {doc['serial_number']}",
            html=build_status_email(doc, "approved"),
        )
    return HTMLResponse(
        _html_page(
            "Approved!",
            "#22c55e",
            "✓",
            "Document Approved!",
            "The document has been successfully approved and the submitter has been notified.",
            doc["serial_number"],
            doc["title"],
        )
    )


@api_router.get("/approvals/reject/{token}", response_class=HTMLResponse)
async def reject_form(token: str):
    r = await _sb(
        lambda: (
            supabase.table("approval_tokens").select("*").eq("token", token).execute()
        )
    )
    if not r.data:
        return HTMLResponse(
            _html_page(
                "Invalid",
                "#ef4444",
                "✗",
                "Invalid Link",
                "This rejection link is invalid or has expired.",
            ),
            status_code=400,
        )
    token_doc = r.data[0]
    if token_doc.get("used"):
        return HTMLResponse(
            _html_page(
                "Used",
                "#f59e0b",
                "!",
                "Already Processed",
                "This link has already been used.",
            )
        )
    action_url = f"{BACKEND_URL}/api/approvals/reject/{token}"
    return HTMLResponse(f"""<!DOCTYPE html><html><head><title>Reject Document</title></head>
    <body style="font-family:'Segoe UI',sans-serif;background:#f8fafc;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">
    <div style="background:white;padding:48px;border-radius:12px;box-shadow:0 4px 16px rgba(0,0,0,0.1);max-width:480px;width:90%;">
        <h2 style="color:#1B2A4A;margin:0 0 8px;">Reject Document</h2>
        <p style="color:#64748b;margin:0 0 24px;">Please provide a reason for rejection (optional):</p>
        <form method="POST" action="{action_url}">
            <textarea name="remarks" style="width:100%;border:1px solid #e2e8f0;border-radius:6px;padding:12px;font-size:14px;box-sizing:border-box;resize:vertical;min-height:100px;" placeholder="Rejection reason..."></textarea>
            <button type="submit" style="background:#ef4444;color:white;padding:12px 24px;border-radius:6px;border:none;cursor:pointer;font-weight:600;font-size:14px;margin-top:16px;width:100%;">Confirm Rejection</button>
        </form>
    </div></body></html>""")


@api_router.post("/approvals/reject/{token}", response_class=HTMLResponse)
async def reject_from_email(token: str, request: Request):
    form_data = await request.form()
    remarks = form_data.get("remarks", "")
    r = await _sb(
        lambda: (
            supabase.table("approval_tokens").select("*").eq("token", token).execute()
        )
    )
    if not r.data:
        return HTMLResponse(
            _html_page(
                "Invalid", "#ef4444", "✗", "Invalid Link", "This link is invalid."
            ),
            status_code=400,
        )
    token_doc = r.data[0]
    if token_doc.get("used"):
        return HTMLResponse(
            _html_page(
                "Used",
                "#f59e0b",
                "!",
                "Already Processed",
                "This link has already been used.",
            )
        )
    doc_id = token_doc["document_id"]
    r2 = await _sb(
        lambda: supabase.table("documents").select("*").eq("id", doc_id).execute()
    )
    if not r2.data:
        return HTMLResponse(
            _html_page("Error", "#ef4444", "✗", "Error", "Document not found."),
            status_code=404,
        )
    doc = r2.data[0]
    now = datetime.now(timezone.utc)
    await _sb(
        lambda: (
            supabase.table("documents")
            .update({"status": "rejected", "updated_at": now.isoformat()})
            .eq("id", doc_id)
            .execute()
        )
    )
    await _sb(
        lambda: (
            supabase.table("approval_tokens")
            .update({"used": True})
            .eq("token", token)
            .execute()
        )
    )
    approval = {
        "document_id": doc_id,
        "status": "rejected",
        "action_by": ADMIN_EMAIL,
        "action_date": now.isoformat(),
        "remarks": remarks,
    }
    await _sb(lambda: supabase.table("approvals").insert(approval).execute())
    details = (
        f"Rejected via email. Remarks: {remarks}" if remarks else "Rejected via email"
    )
    audit = {
        "document_id": doc_id,
        "action": "rejected",
        "action_by": ADMIN_EMAIL,
        "timestamp": now.isoformat(),
        "details": details,
    }
    await _sb(lambda: supabase.table("audit_logs").insert(audit).execute())
    doc = _norm(doc)
    submitter = doc.get("generated_by", "")
    if submitter:
        await send_email(
            to=submitter,
            subject=f"Document Rejected: {doc['serial_number']}",
            html=build_status_email(doc, "rejected", remarks),
        )
    return HTMLResponse(
        _html_page(
            "Rejected",
            "#ef4444",
            "✗",
            "Document Rejected",
            "The document has been rejected and the submitter has been notified.",
            doc["serial_number"],
            doc["title"],
        )
    )


# ── Test Email Endpoint ────────────────────────────────────────────────────
@api_router.post("/test-email")
async def test_email(request: Request, user: dict = Depends(get_admin_user)):
    """Admin-only endpoint to verify Resend email configuration."""
    body = await request.json()
    to = body.get("to", user["email"])

    api_key = os.environ.get("RESEND_API_KEY", "").strip()
    if not api_key:
        raise HTTPException(
            status_code=500, detail="RESEND_API_KEY is not set in environment"
        )

    html = """<!DOCTYPE html><html><body style="font-family:'Segoe UI',sans-serif;padding:40px;">
    <div style="max-width:500px;margin:0 auto;background:white;border-radius:8px;padding:32px;box-shadow:0 2px 8px rgba(0,0,0,0.1);">
        <h2 style="color:#1B2A4A;margin:0 0 12px;">✅ Email is working!</h2>
        <p style="color:#475569;">Your Resend configuration is set up correctly for Kovon Document Registry.</p>
    </div></body></html>"""

    try:
        result = await resend.Emails.send_async(
            {
                "from": SENDER_EMAIL,
                "to": [to],
                "subject": "Kovon — Email Configuration Test",
                "html": html,
            }
        )
        return {
            "success": True,
            "message": f"Test email sent to {to}",
            "email_id": result.id,
            "sender": SENDER_EMAIL,
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Email send failed: {type(e).__name__}: {e}"
        )


# ── Register router ────────────────────────────────────────────────────────
app.include_router(api_router)


# ── Startup / Shutdown ─────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    # Ensure storage bucket exists
    try:
        await _sb(
            lambda: supabase.storage.create_bucket(
                "documents", options={"public": True}
            )
        )
        logger.info("Storage bucket 'documents' created.")
    except Exception as e:
        logger.info(f"Storage bucket 'documents' ready (skipped create: {e})")

    # Ensure admin user exists in Supabase Auth
    try:
        r = await _sb(
            lambda: (
                supabase.auth.admin.list_users()
            )
        )
    # Check if admin exists by email in users list
    admin_exists = any(user['email'] == ADMIN_EMAIL for user in (r.users or []))
    if not admin_exists:
        auth_result = await asyncio.to_thread(
            supabase.auth.admin.create_user,
            {
                "email": ADMIN_EMAIL,
                "password": ADMIN_PASSWORD,
                "email_confirm": True,
                "user_metadata": {"name": "Kovon Founders", "role": "admin"},
            },
        )
        if auth_result.user:
            logger.info(f"Admin user created: {ADMIN_EMAIL}")
        else:
            logger.warning(f"Failed to create admin user: {ADMIN_EMAIL}")
    else:
        logger.info(f"Admin user already exists: {ADMIN_EMAIL}")
    except Exception as e:
        logger.error(f"Startup admin setup error: {e}")


@app.on_event("shutdown")
async def shutdown():
    # No persistent connection to close with supabase-py sync client
    pass
