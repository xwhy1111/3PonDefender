from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

UTC = timezone.utc
PACKAGE_NAME = "com.threepon.defender"
DEMO_DEVICE_ID = "9c6f9d0e-1c68-4a88-8e55-5e0f9e3a1401"
STATE_PATH = Path(os.getenv("THREEPON_STATE_PATH", "/srv/threepon/data/server-state.json"))
WEB_ROOT = Path(os.getenv("THREEPON_WEB_ROOT", "/opt/threepon/web/dist"))
DEV_MODE = os.getenv("THREEPON_DEV_MODE", "true").lower() != "false"
PUBLIC_BASE_URL = os.getenv("THREEPON_PUBLIC_BASE_URL", "")
PASSWORDS = PasswordHasher()
STATE_LOCK = threading.RLock()
RELEASE_CACHE_LOCK = threading.Lock()
RELEASE_CACHE_KEY: tuple[Any, ...] | None = None
RELEASE_CACHE_VALUE: dict[str, Any] | None = None
LOCK_SCREEN_INFO_KEY = "device_owner_lock_screen_info"
DEFAULT_LOCK_SCREEN_INFO = "此设备由三胖监管"
MAX_LOCK_SCREEN_INFO_LENGTH = 200
RINGER_PERIODS_KEY = "force_audible_ringer_periods"
MAX_RINGER_PERIODS = 16
RINGER_PERIOD_PATTERN = re.compile(r"(?:[01]\d|2[0-3]):[0-5]\d-(?:[01]\d|2[0-3]):[0-5]\d")


def configured_update_version() -> int:
    try:
        return max(1, int(os.getenv("THREEPON_UPDATE_VERSION_CODE", "24")))
    except ValueError:
        return 24


def now() -> str:
    return datetime.now(UTC).isoformat()


def new_id() -> str:
    return str(uuid.uuid4())


def hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def recovery_key() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    raw = "".join(secrets.choice(alphabet) for _ in range(20))
    return "-".join(raw[i:i + 5] for i in range(0, 20, 5))


def totp(secret: str, at: int | None = None) -> str:
    clean = secret.replace(" ", "").replace("-", "").upper()
    key = base64.b32decode(clean + "=" * ((8 - len(clean) % 8) % 8))
    counter = int((at or int(time.time())) // 30).to_bytes(8, "big")
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 15
    code = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return f"{code % 1_000_000:06d}"


def valid_totp(secret: str, code: str) -> bool:
    try:
        return any(hmac.compare_digest(totp(secret, int(time.time()) + drift), code.strip()) for drift in (-30, 0, 30))
    except Exception:
        return False


def valid_origin(raw: str) -> str:
    parsed = urlparse(raw.strip())
    if not (parsed.scheme == "https" or (DEV_MODE and parsed.scheme == "http")) or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("管理台地址必须是可访问的 HTTP(S) origin")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("管理台地址不能包含路径、查询参数或片段")
    host = parsed.hostname
    authority = host if ":" not in host else f"[{host}]"
    if parsed.port and not ((parsed.scheme == "http" and parsed.port == 80) or (parsed.scheme == "https" and parsed.port == 443)):
        authority += f":{parsed.port}"
    return f"{parsed.scheme}://{authority}"


def setting(key: str, category: str, label: str, description: str, kind: str, value: Any, supported: bool = True, high_risk: bool = False) -> dict[str, Any]:
    return {"key": key, "category": category, "label": label, "description": description, "kind": kind, "value": value, "supported": supported, "high_risk": high_risk, "status": "applied", "updated_at": now()}


def normalize_ringer_periods(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_RINGER_PERIODS:
        raise ValueError(f"禁止静音时段必须是最多 {MAX_RINGER_PERIODS} 项的列表")
    normalized: list[str] = []
    for raw in value:
        if not isinstance(raw, str):
            raise ValueError("禁止静音时段必须是文本")
        period = raw.strip()
        if not RINGER_PERIOD_PATTERN.fullmatch(period):
            raise ValueError("禁止静音时段格式必须为 HH:mm-HH:mm")
        start, end = period.split("-", 1)
        if start == end:
            raise ValueError("禁止静音时段的开始和结束时间不能相同")
        if period not in normalized:
            normalized.append(period)
    return normalized


def default_settings() -> list[dict[str, Any]]:
    rows = [
        ("block_user_install", "应用管理", "禁止用户安装应用", "阻止浏览器、文件管理器和应用商店直接安装。", "boolean", True, True, True),
        ("block_unknown_sources", "应用管理", "禁止未知来源", "关闭未知来源 APK 安装入口。", "boolean", True, True, False),
        ("defender_uninstall_blocked", "应用管理", "3Pon Defender 防卸载", "阻止被管控端卸载本软件。", "boolean", True, True, True),
        ("defender_background_protection", "应用管理", "Defender 后台保护", "保持轮询前台服务、开机恢复和 Xiaomi 后台保护引导。", "boolean", True, True, False),
        ("suspend_unapproved_apps", "应用管理", "暂停未批准应用", "将未进入审批清单的应用置为暂停状态。", "boolean", True, True, True),
        ("restrict_account_changes", "用户限制", "限制账号变更", "限制用户自行添加或删除系统账号。", "boolean", False, True, True),
        ("restrict_usb_debugging", "用户限制", "限制 USB 调试", "完成 ADB 注册后关闭调试入口。", "boolean", True, True, True),
        ("restrict_developer_options", "用户限制", "限制开发者选项", "限制用户打开开发者选项。", "boolean", True, True, True),
        ("camera_disabled", "硬件与隐私", "禁用摄像头", "禁用设备摄像头。", "boolean", False, True, True),
        ("microphone_disabled", "硬件与隐私", "禁用麦克风", "公开 Device Owner API 不提供通用麦克风禁用策略。", "boolean", False, False, True),
        ("screen_capture_disabled", "硬件与隐私", "禁止截屏录屏", "阻止系统截屏和录屏。", "boolean", True, True, True),
        ("status_bar_disabled", "系统界面", "限制状态栏", "隐藏或限制状态栏操作。", "boolean", False, True, True),
        ("lock_task_mode", "系统界面", "Lock Task 模式", "将设备锁定在受控应用集合中。", "boolean", False, True, True),
        ("always_on_vpn", "网络", "Always-on VPN", "仅在已配置联网限制时启用设备级 VPN。", "boolean", False, True, True),
        ("vpn_lockdown", "网络", "VPN Lockdown", "VPN 断开时阻止应用绕过管控联网。", "boolean", False, True, True),
        ("network_default_mode", "网络", "默认联网策略", "未明确允许的应用默认阻断。", "text", "deny_unlisted", True, True),
        ("factory_reset_blocked", "设备生命周期", "限制系统恢复出厂", "限制系统界面发起的恢复出厂操作。", "boolean", True, True, True),
        ("auto_time_enabled", "设备生命周期", "自动设置时间", "使用网络或系统自动设置时间。", "boolean", True, True, False),
        ("auto_time_zone_enabled", "设备生命周期", "自动设置时区", "使用网络自动设置设备时区。", "boolean", True, True, False),
        ("external_storage_disabled", "设备生命周期", "限制外部存储", "限制外部存储访问。", "boolean", False, True, True),
        ("password_min_length", "锁屏与安全", "最小密码长度", "设备锁屏密码的最小长度。", "integer", 6, True, True),
        ("max_time_to_lock_ms", "锁屏与安全", "最长自动锁屏时间", "限制设备保持解锁的最长时间，0 表示不设置上限。", "integer", 0, True, True),
        (LOCK_SCREEN_INFO_KEY, "锁屏与安全", "锁屏监管提示", "自定义设备锁屏上显示的监管信息，留空可清除。", "text", DEFAULT_LOCK_SCREEN_INFO, True, False),
        ("wifi_config_lockdown", "网络与系统", "锁定 Wi-Fi 配置", "限制用户修改设备所有者配置的 Wi-Fi。", "boolean", False, True, True),
        ("time_zone", "网络与系统", "设置时区", "使用 Android Device Owner 公开接口设置设备时区，例如 Asia/Shanghai。", "text", "Asia/Shanghai", True, True),
        ("stay_awake_while_plugged_in", "网络与系统", "充电时保持唤醒", "设置设备插电时保持唤醒的电源类型位掩码，0 表示关闭。", "integer", 0, True, True),
        ("screen_brightness", "系统设置", "屏幕亮度", "设置系统亮度，范围 1 到 255。", "integer", 128, True, False),
        ("screen_brightness_mode", "系统设置", "自动亮度", "在自动亮度和手动亮度之间切换。", "text", "manual", True, False),
        ("screen_off_timeout_ms", "系统设置", "自动息屏", "设置无操作后自动关闭屏幕的等待时间。", "integer", 60000, True, False),
        ("force_audible_ringer", "系统设置", "强制来电响铃", "禁止切换为静音或仅震动，并保持来电铃声音量最大；媒体和闹铃音量不受影响。", "boolean", False, True, False),
        (RINGER_PERIODS_KEY, "系统设置", "禁止静音时段", "按设备本地时间执行；空列表表示全天，支持跨午夜时段。", "string_list", [], True, False),
        ("keyguard_features_restricted", "锁屏与安全", "限制锁屏快捷能力", "限制锁屏状态下的快捷操作。", "boolean", False, True, True),
        ("call_screening_enabled", "电话", "启用电话筛选", "启用电话白名单筛选服务。", "boolean", True, True, True),
        ("call_allowlist", "电话", "电话白名单", "允许的联系人号码列表。", "string_list", ["110", "120", "119"], True, True),
        ("contacts_only_calls", "电话", "仅允许通讯录来电", "开启后，仅紧急号码、电话白名单和设备通讯录中保存的号码可以呼入。需要被管控端授予读取通讯录权限。", "boolean", False, True, True),
    ]
    return [setting(*row) for row in rows]


def default_basic_policy() -> dict[str, Any]:
    return {"installation_approval_required": True, "default_network_mode": "deny_unlisted", "defender_self_protection": True, "background_protection_enabled": True, "call_screening_enabled": True, "call_allowlist": ["110", "120", "119"], "contacts_only_calls": False, "suspended_packages": []}


CALL_POLICY_KEYS = ("call_screening_enabled", "call_allowlist", "contacts_only_calls")


def canonicalize_call_policy(policy: dict[str, Any]) -> bool:
    """Contact-only filtering cannot work while the master screening switch is off."""
    if policy.get("contacts_only_calls") is True and policy.get("call_screening_enabled") is not True:
        policy["call_screening_enabled"] = True
        return True
    return False


def normalize_call_allowlist(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > 200:
        raise HTTPException(400, "电话白名单格式无效")
    cleaned: list[str] = []
    for number in value:
        normalized = re.sub(r"[\s()-]", "", str(number))
        if not re.fullmatch(r"\+?\d{3,20}", normalized):
            raise HTTPException(400, "电话白名单包含无效号码")
        if normalized not in cleaned:
            cleaned.append(normalized)
    return cleaned


def empty_app_catalog() -> dict[str, Any]:
    return {"revision": "", "updated_at": None, "apps": []}


def default_state() -> dict[str, Any]:
    device_id = "9c6f9d0e-1c68-4a88-8e55-5e0f9e3a1401"
    base = PUBLIC_BASE_URL or ("http://localhost:8015" if DEV_MODE else "https://control.example.com")
    return {"version": 5, "admin": None, "recovery_keys": [{"id": new_id(), "value": recovery_key(), "used": False, "used_at": None} for _ in range(8)], "sessions": {}, "pairing_sessions": {}, "devices": {device_id: {"id": device_id, "name": "长辈手机 · Xiaomi 14", "model": "Xiaomi 14", "manufacturer": "Xiaomi", "android_api": 36, "hyperos_version": "HyperOS 3/4 · capability probe", "base_url": base, "status": "offline", "last_seen_at": now(), "consent_version": "2026-09-13", "consented_at": now(), "policy_version": 1, "device_token_hash": hash_bytes(b"dev-device-token"), "apps_revision": "", "apps_updated_at": None, "app_count": 0, "update_status": "idle", "update_version_code": 0, "update_message": None, "update_updated_at": None}}, "settings": {device_id: default_settings()}, "basic_policies": {device_id: default_basic_policy()}, "app_catalog": {device_id: empty_app_catalog()}, "commands": [], "install_requests": [], "audit": [{"id": new_id(), "at": now(), "event": "system.ready", "target": device_id, "message": "FastAPI 控制服务已启动"}]}


def load_state() -> dict[str, Any]:
    try:
        state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        base = default_state()
        base.update(state)
        migrate_state(base)
        return base
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        state = default_state()
        legacy_path = STATE_PATH.with_name("admin-state.json")
        try:
            legacy = json.loads(legacy_path.read_text(encoding="utf-8"))
            if legacy.get("admin_username") and legacy.get("admin_password_hash") and legacy.get("totp_secret"):
                state["admin"] = {"username": legacy["admin_username"], "password_hash": legacy["admin_password_hash"], "totp_secret": legacy["totp_secret"]}
            if legacy.get("recovery_keys"):
                state["recovery_keys"] = legacy["recovery_keys"]
        except (FileNotFoundError, json.JSONDecodeError, OSError, KeyError):
            pass
        migrate_state(state)
        return state


def migrate_state(state: dict[str, Any]) -> None:
    """Add fields introduced by the real application inventory/update flow."""
    state.setdefault("version", 2)
    previous_version = int(state.get("version", 1))
    state.setdefault("sessions", {})
    state.setdefault("pairing_sessions", {})
    state.setdefault("devices", {})
    state.setdefault("settings", {})
    state.setdefault("basic_policies", {})
    state.setdefault("app_catalog", {})
    state.setdefault("commands", [])
    state.setdefault("install_requests", [])
    state.setdefault("audit", [])
    default_setting_rows = {row["key"]: row for row in default_settings()}
    for device_id, device in state["devices"].items():
        device.setdefault("id", device_id)
        device.setdefault("apps_revision", "")
        device.setdefault("apps_updated_at", None)
        device.setdefault("app_count", 0)
        device.setdefault("update_status", "idle")
        device.setdefault("update_version_code", 0)
        device.setdefault("update_message", None)
        device.setdefault("update_updated_at", None)
        rows = state["settings"].setdefault(device_id, default_settings())
        known = {row.get("key") for row in rows}
        lock_screen_info_added = False
        ringer_periods_added = False
        for key, row in default_setting_rows.items():
            if key not in known:
                added = dict(row)
                if key in {LOCK_SCREEN_INFO_KEY, RINGER_PERIODS_KEY}:
                    added["status"] = "pending"
                if key == LOCK_SCREEN_INFO_KEY:
                    lock_screen_info_added = True
                if key == RINGER_PERIODS_KEY:
                    ringer_periods_added = True
                rows.append(added)
        policy = state["basic_policies"].setdefault(device_id, default_basic_policy())
        basic_policy_changed = False
        for key, value in default_basic_policy().items():
            if key not in policy:
                policy[key] = value
                basic_policy_changed = True
        call_policy_changed = canonicalize_call_policy(policy)
        call_setting_rows = {row.get("key"): row for row in rows}
        for key in CALL_POLICY_KEYS:
            item = call_setting_rows.get(key)
            if item and item.get("value") != policy.get(key):
                item["value"] = policy.get(key)
                item["status"] = "pending"
                item["updated_at"] = now()
                call_policy_changed = True
        # Keep the two Android install restrictions consistent with the
        # user-facing installation approval switch after a version upgrade.
        install_value = bool(policy.get("installation_approval_required", True))
        for key in ("block_user_install", "block_unknown_sources"):
            item = next((row for row in rows if row.get("key") == key), None)
            if item:
                item["value"] = install_value
        state["app_catalog"].setdefault(device_id, empty_app_catalog())
        lock_screen_info = next((row for row in rows if row.get("key") == LOCK_SCREEN_INFO_KEY), None)
        retry_failed_lock_screen_info = previous_version < 3 and lock_screen_info is not None and lock_screen_info.get("status") == "failed"
        if retry_failed_lock_screen_info:
            lock_screen_info["status"] = "pending"
            lock_screen_info["updated_at"] = now()
        if lock_screen_info_added or retry_failed_lock_screen_info or ringer_periods_added or basic_policy_changed or call_policy_changed:
            device["policy_version"] = max(1, int(device.get("policy_version", 1))) + 1
    state["version"] = max(int(state.get("version", 1)), 5)


STATE = load_state()


def save_state() -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="state-", suffix=".json", dir=STATE_PATH.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(STATE, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, STATE_PATH)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def audit(event: str, target: str, message: str) -> None:
    STATE["audit"].append({"id": new_id(), "at": now(), "event": event, "target": target, "message": message})
    STATE["audit"] = STATE["audit"][-500:]


def signing_key() -> Ed25519PrivateKey:
    key_path = Path(os.getenv("THREEPON_POLICY_SIGNING_KEY_PATH", str(STATE_PATH.with_name("policy-signing-key.bin"))))
    try:
        raw = base64.b64decode(os.getenv("THREEPON_POLICY_SIGNING_KEY", ""))
        if len(raw) == 32:
            return Ed25519PrivateKey.from_private_bytes(raw)
    except Exception:
        pass
    try:
        raw = key_path.read_bytes()
        if len(raw) == 32:
            return Ed25519PrivateKey.from_private_bytes(raw)
    except OSError:
        pass
    key = Ed25519PrivateKey.generate()
    try:
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
    except OSError:
        pass
    return key


SIGNING_KEY = signing_key()
PUBLIC_KEY = base64.b64encode(SIGNING_KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


class Setup(BaseModel):
    username: str
    password: str
    totp_secret: str
    otp: str


class Login(BaseModel):
    username: str
    password: str
    otp: str


class DeviceAdminVerify(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class RecoveryReset(BaseModel):
    recovery_key: str
    username: str
    password: str
    totp_secret: str
    otp: str | None = None


class PairingSessionRequest(BaseModel):
    base_url: str
    device_name: str | None = None


class PairingClaim(BaseModel):
    session_id: str
    pairing_token: str
    device_name: str
    package_name: str
    model: str
    manufacturer: str
    android_api: int
    hyperos_version: str
    device_owner: bool
    consented: bool
    consent_version: str


class PolicyUpdate(BaseModel):
    settings: list[dict[str, Any]] = Field(default_factory=list)
    reason: str | None = None


class Command(BaseModel):
    device_id: str
    kind: str
    requires_confirmation: bool = False
    payload: dict[str, Any] = Field(default_factory=dict)


class Ack(BaseModel):
    device_id: str
    command_id: str | None = None
    status: str = "applied"
    message: str | None = None
    policy_version: int | None = None
    failed_settings: list[str] = Field(default_factory=list)
    failure_details: dict[str, str] = Field(default_factory=dict)


class AppInventoryPayload(BaseModel):
    device_id: str
    revision: str = Field(min_length=1, max_length=128)
    apps: list[dict[str, Any]] = Field(default_factory=list)


class UpdateStatus(BaseModel):
    device_id: str
    status: str
    version_code: int = 0
    message: str | None = None


class DeviceRuntimeStatus(BaseModel):
    device_id: str
    device_owner_active: bool
    call_screening_role_available: bool
    call_screening_role_held: bool
    contacts_permission_granted: bool
    call_screening_enabled: bool
    contacts_only_calls: bool
    last_screened_call_at: str | None = None
    screened_call_count: int = Field(default=0, ge=0)
    blocked_call_count: int = Field(default=0, ge=0)


class AppAction(BaseModel):
    action: str


class AppPermissionAction(BaseModel):
    permission: str
    grant_state: str


app = FastAPI(title="3Pon Defender Control API", version="0.2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


def admin_required(authorization: str | None = Header(default=None)) -> str:
    token = (authorization or "").removeprefix("Bearer ").strip()
    with STATE_LOCK:
        if token and token in STATE["sessions"] and STATE["sessions"][token] > time.time():
            return token
    raise HTTPException(401, "需要管理员登录")


def device_required(device_id: str, token: str | None) -> dict[str, Any]:
    with STATE_LOCK:
        device = STATE["devices"].get(device_id)
        if not device:
            raise HTTPException(404, "设备不存在")
        expected = device.get("device_token_hash", "")
        if not token or not hmac.compare_digest(hash_bytes(token.encode()), expected):
            raise HTTPException(401, "设备凭据无效")
        return device


def release_info(device_id: str) -> dict[str, Any] | None:
    global RELEASE_CACHE_KEY, RELEASE_CACHE_VALUE
    path = os.getenv("THREEPON_UPDATE_APK_PATH", "")
    if not path:
        return None
    artifact = Path(path)
    try:
        stat = artifact.stat()
    except OSError:
        return None
    version_code = configured_update_version()
    version_name = os.getenv("THREEPON_UPDATE_VERSION_NAME", "0.1.23")
    base = STATE["devices"].get(device_id, {}).get("base_url") or PUBLIC_BASE_URL or "http://localhost:8015"
    cache_key = (str(artifact), stat.st_mtime_ns, stat.st_size, version_code, version_name, base, os.getenv("THREEPON_ANDROID_SIGNER_SHA256", "").lower(), os.getenv("THREEPON_UPDATE_MANDATORY", "false").lower())
    with RELEASE_CACHE_LOCK:
        if cache_key == RELEASE_CACHE_KEY:
            return dict(RELEASE_CACHE_VALUE) if RELEASE_CACHE_VALUE else None
        if not artifact.is_file():
            return None
        digest = hash_bytes(artifact.read_bytes())
    url = f"{base}/api/v1/device/update-artifacts/{version_code}?device_id={device_id}"
    payload = {"package_name": PACKAGE_NAME, "version_code": version_code, "version_name": version_name, "apk_url": url, "sha256": digest, "signer_sha256": os.getenv("THREEPON_ANDROID_SIGNER_SHA256", "").lower(), "mandatory": os.getenv("THREEPON_UPDATE_MANDATORY", "false").lower() == "true", "published_at": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat()}
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    result = {**payload, "manifest_signature": base64.b64encode(SIGNING_KEY.sign(raw)).decode(), "signed_payload": base64.b64encode(raw).decode()}
    with RELEASE_CACHE_LOCK:
        RELEASE_CACHE_KEY, RELEASE_CACHE_VALUE = cache_key, result
    return dict(result)


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "service": "3pon-defender", "transport": "http-polling", "poll_interval_seconds": 10}


@app.get("/api/v1/auth/status")
def auth_status() -> dict[str, Any]:
    return {"ok": True, "initialized": STATE["admin"] is not None, "setup_required": STATE["admin"] is None}


@app.post("/api/v1/auth/setup")
def setup_admin(input: Setup) -> JSONResponse:
    secret = input.totp_secret.replace(" ", "").replace("-", "").upper()
    if len(input.username.strip()) < 3 or len(input.username.strip()) > 64 or len(input.password) < 9 or not valid_totp(secret, input.otp):
        raise HTTPException(400, "用户名、密码、TOTP 密钥或验证码不符合要求")
    with STATE_LOCK:
        if STATE["admin"] is not None:
            raise HTTPException(409, "管理员已经初始化，请直接登录")
        STATE["admin"] = {"username": input.username.strip(), "password_hash": PASSWORDS.hash(input.password), "totp_secret": secret}
        audit("admin.initialized", "admin", "首次创建管理员账号并启用 TOTP")
        token = new_id()
        STATE["sessions"][token] = time.time() + 86400
        save_state()
    return JSONResponse({"ok": True, "status": "initialized", "token": token, "user": input.username.strip(), "demo_mode": DEV_MODE})


@app.post("/api/v1/auth/login")
def login(input: Login) -> dict[str, Any]:
    admin = STATE["admin"]
    if not admin:
        raise HTTPException(428, "请先完成首次管理员初始化")
    try:
        valid = input.username == admin["username"] and PASSWORDS.verify(admin["password_hash"], input.password) and valid_totp(admin["totp_secret"], input.otp)
    except Exception:
        valid = False
    if not valid:
        raise HTTPException(401, "用户名、密码或 OTP 不正确")
    with STATE_LOCK:
        token = new_id()
        STATE["sessions"][token] = time.time() + 86400
        audit("admin.login", "admin", "管理员登录成功")
        save_state()
    return {"ok": True, "token": token, "user": admin["username"], "demo_mode": DEV_MODE}


@app.post("/api/v1/auth/recovery/reset")
def recovery_reset(input: RecoveryReset) -> dict[str, Any]:
    if len(input.password) < 9 or len(input.username.strip()) < 3:
        raise HTTPException(400, "新管理员账号或密码不符合要求")
    with STATE_LOCK:
        key = next((item for item in STATE["recovery_keys"] if not item["used"] and hmac.compare_digest(item["value"], input.recovery_key.strip().upper())), None)
        if not key:
            raise HTTPException(401, "恢复密钥无效或已经使用")
        secret = input.totp_secret.replace(" ", "").replace("-", "").upper()
        if not valid_totp(secret, input.otp or ""):
            raise HTTPException(400, "新的 TOTP 验证码不正确")
        key["used"], key["used_at"] = True, now()
        STATE["admin"] = {"username": input.username.strip(), "password_hash": PASSWORDS.hash(input.password), "totp_secret": secret}
        STATE["sessions"] = {}
        audit("admin.recovery.reset", "admin", "使用一次性恢复密钥重置管理员凭据")
        save_state()
    return {"ok": True, "status": "reset"}


@app.get("/api/v1/auth/recovery-keys")
def recovery_keys(_: str = Depends(admin_required)) -> dict[str, Any]:
    return {"ok": True, "keys": STATE["recovery_keys"]}


@app.post("/api/v1/pairing/sessions")
def create_pairing(input: PairingSessionRequest, _: str = Depends(admin_required)) -> dict[str, Any]:
    try:
        base = valid_origin(input.base_url)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    session_id, token = new_id(), secrets.token_urlsafe(32)
    expires = datetime.now(UTC) + timedelta(minutes=10)
    with STATE_LOCK:
        STATE["pairing_sessions"][session_id] = {"token_hash": hash_bytes(token.encode()), "base_url": base, "device_name": input.device_name or "长辈手机", "expires_at": expires.timestamp()}
        audit("device.pairing.created", session_id, "管理员创建一次性扫码配对会话")
        save_state()
    payload = {"kind": "3pon_pairing", "version": 1, "session_id": session_id, "pairing_token": token, "base_url": base, "server_public_key": PUBLIC_KEY, "update_manifest_url": f"{base}/api/v1/device/update-manifest", "expires_at": expires.isoformat()}
    return {"ok": True, "session_id": session_id, "base_url": base, "server_public_key": PUBLIC_KEY, "update_manifest_url": payload["update_manifest_url"], "expires_at": payload["expires_at"], "qr_payload": json.dumps(payload, separators=(",", ":"), ensure_ascii=False)}


@app.post("/api/v1/device/pairing/claim")
def claim_pairing(input: PairingClaim) -> dict[str, Any]:
    if not input.consented:
        raise HTTPException(400, "必须先在被管控端明确同意功能和隐私说明")
    if not input.device_owner:
        raise HTTPException(400, "被管控端必须先完成 Device Owner 注册")
    if input.package_name != PACKAGE_NAME or not input.consent_version.strip():
        raise HTTPException(400, "被管控端身份或同意版本无效")
    with STATE_LOCK:
        session = STATE["pairing_sessions"].get(input.session_id)
        if not session or session["expires_at"] <= time.time():
            STATE["pairing_sessions"].pop(input.session_id, None)
            raise HTTPException(410, "配对二维码不存在、已使用或已过期")
        if not hmac.compare_digest(hash_bytes(input.pairing_token.encode()), session["token_hash"]):
            raise HTTPException(401, "配对二维码凭据无效")
        STATE["pairing_sessions"].pop(input.session_id)
        device_id, device_token = new_id(), secrets.token_urlsafe(32)
        STATE["devices"][device_id] = {"id": device_id, "name": input.device_name.strip() or session["device_name"], "model": input.model, "manufacturer": input.manufacturer, "android_api": input.android_api, "hyperos_version": input.hyperos_version, "base_url": session["base_url"], "status": "online", "last_seen_at": now(), "consent_version": input.consent_version, "consented_at": now(), "policy_version": 1, "device_token_hash": hash_bytes(device_token.encode()), "apps_revision": "", "apps_updated_at": None, "app_count": 0, "update_status": "idle", "update_version_code": 0, "update_message": None, "update_updated_at": None}
        STATE["settings"][device_id], STATE["basic_policies"][device_id], STATE["app_catalog"][device_id] = default_settings(), default_basic_policy(), empty_app_catalog()
        audit("device.pairing.claimed", device_id, "被管控端在明确同意后完成扫码配对")
        save_state()
    return {"ok": True, "device_id": device_id, "device_token": device_token, "base_url": session["base_url"], "server_public_key": PUBLIC_KEY, "update_manifest_url": f"{session['base_url']}/api/v1/device/update-manifest", "consent_version": input.consent_version}


@app.post("/api/v1/device/admin-verify")
def device_admin_verify(input: DeviceAdminVerify, x_device_token: str | None = Header(default=None)) -> dict[str, Any]:
    device_id = ""
    with STATE_LOCK:
        for candidate_id, candidate in STATE["devices"].items():
            expected = candidate.get("device_token_hash", "")
            if x_device_token and expected and hmac.compare_digest(hash_bytes(x_device_token.encode()), expected):
                device_id = candidate_id
                break
        if not device_id:
            raise HTTPException(401, "设备凭据无效")
        admin = STATE.get("admin")
        if not admin:
            raise HTTPException(428, "管控端尚未初始化管理员")
        try:
            valid = PASSWORDS.verify(admin["password_hash"], input.password)
        except Exception:
            valid = False
        if not valid:
            raise HTTPException(401, "管理员密码不正确")
        audit("device.admin.verify", device_id, "被管控端设置页管理员密码验证成功")
        save_state()
    return {"ok": True, "device_id": device_id}


def device_view(device: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in device.items() if key != "device_token_hash"}


def ordered_device_views() -> list[dict[str, Any]]:
    devices = [device_view(item) for item in STATE["devices"].values()]
    # Keep the development fixture available, but never make it the default
    # target once a real paired device exists.
    devices.sort(key=lambda item: (item["id"] == DEMO_DEVICE_ID, item.get("status") != "online", item.get("last_seen_at", "")), reverse=False)
    return devices


@app.get("/api/v1/device/poll")
def device_poll(device_id: str = Query(...), x_device_token: str | None = Header(default=None)) -> dict[str, Any]:
    with STATE_LOCK:
        device = device_required(device_id, x_device_token)
        device["status"], device["last_seen_at"] = "online", now()
        queued = [item.copy() for item in STATE["commands"] if item["device_id"] == device_id and item["status"] in ("queued", "delivered")]
        for item in STATE["commands"]:
            if item["device_id"] == device_id and item["status"] == "queued":
                item["status"] = "delivered"
        manifest = release_info(device_id)
        save_state()
        return {"ok": True, "server_time": now(), "device_id": device_id, "policy_version": device.get("policy_version", 1), "settings": STATE["settings"].get(device_id, []), "basic_policy": STATE["basic_policies"].get(device_id, {}), "commands": queued, "update": manifest, "server_public_key": PUBLIC_KEY}


def sanitize_app_row(raw: dict[str, Any]) -> dict[str, Any]:
    package_name = str(raw.get("package_name", "")).strip()
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.]{0,254}", package_name):
        raise ValueError("应用包名格式无效")
    permissions = raw.get("permissions", [])
    if not isinstance(permissions, list):
        permissions = []
    permission_details = raw.get("permission_details", [])
    if not isinstance(permission_details, list):
        permission_details = []
    clean_permission_details = []
    for item in permission_details[:64]:
        if not isinstance(item, dict):
            continue
        permission = str(item.get("name", ""))[:160]
        grant_state = str(item.get("grant_state", "default"))
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.]{0,159}", permission) or grant_state not in {"default", "granted", "denied"}:
            continue
        clean_permission_details.append({
            "name": permission,
            "label": str(item.get("label", permission.rsplit(".", 1)[-1]))[:80],
            "runtime": bool(item.get("runtime", False)),
            "controllable": bool(item.get("controllable", False)),
            "granted": bool(item.get("granted", False)),
            "grant_state": grant_state,
        })
    return {
        "package_name": package_name,
        "label": str(raw.get("label", package_name))[:120],
        "version_name": str(raw.get("version_name", ""))[:80],
        "version_code": max(0, int(raw.get("version_code", 0))),
        "target_sdk": max(0, int(raw.get("target_sdk", 0))),
        "uid": int(raw.get("uid", -1)),
        "system_app": bool(raw.get("system_app", False)),
        "enabled": bool(raw.get("enabled", False)),
        "suspended": bool(raw.get("suspended", False)),
        "hidden": bool(raw.get("hidden", False)),
        "network_blocked": bool(raw.get("network_blocked", False)),
        "installer": str(raw.get("installer", ""))[:120] if raw.get("installer") not in (None, "") else None,
        "signer_sha256": str(raw.get("signer_sha256", "")).lower()[:128],
        "permissions": [str(item)[:160] for item in permissions[:64]],
        "permission_details": clean_permission_details,
    }


@app.post("/api/v1/device/apps")
def upload_device_apps(input: AppInventoryPayload, x_device_token: str | None = Header(default=None)) -> dict[str, Any]:
    if input.device_id not in STATE["devices"]:
        raise HTTPException(404, "设备不存在")
    if len(input.apps) > 1000:
        raise HTTPException(413, "应用清单数量超过限制")
    try:
        rows = [sanitize_app_row(item) for item in input.apps]
    except (TypeError, ValueError, OverflowError) as exc:
        raise HTTPException(400, str(exc)) from exc
    with STATE_LOCK:
        device = device_required(input.device_id, x_device_token)
        catalog = STATE["app_catalog"].setdefault(input.device_id, empty_app_catalog())
        changed = catalog.get("revision") != input.revision
        catalog.update({"revision": input.revision, "updated_at": now(), "apps": rows})
        device.update({"apps_revision": input.revision, "apps_updated_at": catalog["updated_at"], "app_count": len(rows), "status": "online", "last_seen_at": catalog["updated_at"]})
        if changed:
            audit("device.apps.synced", input.device_id, f"设备上传应用清单，共 {len(rows)} 个应用")
        save_state()
    return {"ok": True, "device_id": input.device_id, "revision": input.revision, "app_count": len(rows), "updated_at": catalog["updated_at"]}


@app.post("/api/v1/device/update-status")
def upload_update_status(input: UpdateStatus, x_device_token: str | None = Header(default=None)) -> dict[str, Any]:
    allowed = {"idle", "checking", "downloading", "verifying", "installing", "pending_user_action", "applied", "failed"}
    if input.status not in allowed:
        raise HTTPException(400, "未知更新状态")
    with STATE_LOCK:
        device = device_required(input.device_id, x_device_token)
        updated = now()
        device.update({"update_status": input.status, "update_version_code": max(0, input.version_code), "update_message": (input.message or "")[:500] or None, "update_updated_at": updated, "status": "online", "last_seen_at": updated})
        if input.status in {"applied", "failed"}:
            audit("device.update." + input.status, input.device_id, f"设备更新状态：{input.status} v{input.version_code} {(input.message or '')[:160]}")
        save_state()
    return {"ok": True, "status": input.status, "updated_at": updated}


@app.post("/api/v1/device/runtime-status")
def upload_device_runtime_status(input: DeviceRuntimeStatus, x_device_token: str | None = Header(default=None)) -> dict[str, Any]:
    with STATE_LOCK:
        device = device_required(input.device_id, x_device_token)
        updated = now()
        device.update({
            "device_owner_active": input.device_owner_active,
            "call_screening_role_available": input.call_screening_role_available,
            "call_screening_role_held": input.call_screening_role_held,
            "contacts_permission_granted": input.contacts_permission_granted,
            "call_screening_enabled": input.call_screening_enabled,
            "contacts_only_calls": input.contacts_only_calls,
            "last_screened_call_at": (input.last_screened_call_at or "")[:64] or None,
            "screened_call_count": input.screened_call_count,
            "blocked_call_count": input.blocked_call_count,
            "call_screening_status_updated_at": updated,
            "status": "online",
            "last_seen_at": updated,
        })
        save_state()
    return {"ok": True, "updated_at": updated}


@app.post("/api/v1/device/command-ack")
def command_ack(input: Ack, x_device_token: str | None = Header(default=None)) -> dict[str, Any]:
    with STATE_LOCK:
        device = device_required(input.device_id, x_device_token)
        if input.command_id:
            for item in STATE["commands"]:
                if item["id"] == input.command_id and item["device_id"] == input.device_id:
                    item["status"], item["acknowledged_at"] = input.status, now()
        if input.policy_version is not None:
            device["policy_version"] = max(device.get("policy_version", 0), input.policy_version)
            settings = {item["key"]: item for item in STATE["settings"].get(input.device_id, [])}
            for key, item in settings.items():
                if item.get("status") in {"pending", "failed"}:
                    item["status"] = "failed" if key in input.failed_settings else "applied"
            if input.failed_settings:
                failures = []
                for key in input.failed_settings:
                    detail = input.failure_details.get(key, "").strip()[:300]
                    failures.append(f"{key} ({detail})" if detail else key)
                audit("policy.apply.failed", input.device_id, "设备报告策略执行失败: " + ", ".join(failures))
        device["status"], device["last_seen_at"] = "online", now()
        save_state()
    return {"ok": True}


@app.get("/api/v1/device/update-manifest")
def update_manifest(device_id: str = Query(...), x_device_token: str | None = Header(default=None)) -> dict[str, Any]:
    device_required(device_id, x_device_token)
    return release_info(device_id) or {"ok": True, "available": False}


@app.get("/api/v1/device/update-artifacts/{version}")
def update_artifact(version: int, device_id: str = Query(...), x_device_token: str | None = Header(default=None)) -> FileResponse:
    device_required(device_id, x_device_token)
    manifest = release_info(device_id)
    if not manifest or version != int(manifest["version_code"]):
        raise HTTPException(404, "更新版本不存在")
    path = os.getenv("THREEPON_UPDATE_APK_PATH", "")
    if not path or not Path(path).is_file():
        raise HTTPException(404, "更新包不存在")
    return FileResponse(path, media_type="application/vnd.android.package-archive", filename=f"threepon-defender-{version}.apk", headers={"Cache-Control": "no-store"})


@app.get("/api/v1/dashboard")
def dashboard(_: str = Depends(admin_required)) -> dict[str, Any]:
    with STATE_LOCK:
        devices = ordered_device_views()
        online = sum(1 for item in devices if item["status"] == "online" and datetime.fromisoformat(item["last_seen_at"]).timestamp() > time.time() - 45)
        return {"ok": True, "devices": devices, "pending_install_requests": sum(item["status"] == "pending" for item in STATE["install_requests"]), "online_devices": online, "pending_commands": sum(item["status"] in ("queued", "delivered") for item in STATE["commands"])}


@app.get("/api/v1/devices")
def devices(_: str = Depends(admin_required)) -> dict[str, Any]:
    return {"ok": True, "devices": ordered_device_views()}


def get_device(device_id: str) -> dict[str, Any]:
    device = STATE["devices"].get(device_id)
    if not device:
        raise HTTPException(404, "设备不存在")
    return device


@app.get("/api/v1/devices/{device_id}/runtime-status")
def device_runtime_status(device_id: str, _: str = Depends(admin_required)) -> dict[str, Any]:
    device = get_device(device_id)
    keys = (
        "device_owner_active",
        "call_screening_role_available",
        "call_screening_role_held",
        "contacts_permission_granted",
        "call_screening_enabled",
        "contacts_only_calls",
        "last_screened_call_at",
        "screened_call_count",
        "blocked_call_count",
        "call_screening_status_updated_at",
    )
    return {"ok": True, "device_id": device_id, **{key: device.get(key) for key in keys}}


@app.get("/api/v1/devices/{device_id}/capabilities")
def capabilities(device_id: str, _: str = Depends(admin_required)) -> dict[str, Any]:
    get_device(device_id)
    rows = STATE["settings"].get(device_id, [])
    return {"ok": True, "device_id": device_id, "android_api": STATE["devices"][device_id]["android_api"], "manufacturer": STATE["devices"][device_id]["manufacturer"], "model": STATE["devices"][device_id]["model"], "hyperos_version": STATE["devices"][device_id]["hyperos_version"], "supported_policies": [{"key": row["key"], "supported": row["supported"], "reason": None if row["supported"] else row["description"]} for row in rows]}


@app.get("/api/v1/devices/{device_id}/owner-policy")
def owner_policy(device_id: str, _: str = Depends(admin_required)) -> dict[str, Any]:
    get_device(device_id)
    return {"ok": True, "device_id": device_id, "version": STATE["devices"][device_id].get("policy_version", 1), "settings": STATE["settings"].get(device_id, []), "signature": "polling-policy"}


@app.put("/api/v1/devices/{device_id}/owner-policy")
def update_owner_policy(device_id: str, input: PolicyUpdate, _: str = Depends(admin_required)) -> dict[str, Any]:
    get_device(device_id)
    with STATE_LOCK:
        allowed = {item["key"]: item for item in STATE["settings"].get(device_id, [])}
        changed = []
        install_value: bool | None = None
        call_policy_patch: dict[str, Any] = {}
        for patch in input.settings:
            key = str(patch.get("key", ""))
            item = allowed.get(key)
            if item and item["supported"] and "value" in patch:
                value = patch["value"]
                if key in {"block_user_install", "block_unknown_sources"}:
                    if not isinstance(value, bool):
                        raise HTTPException(400, f"{key} 必须是布尔值")
                    install_value = value
                    continue
                if key in {"call_screening_enabled", "contacts_only_calls"}:
                    if not isinstance(value, bool):
                        raise HTTPException(400, f"{key} 必须是布尔值")
                    call_policy_patch[key] = value
                elif key == "call_allowlist":
                    value = normalize_call_allowlist(value)
                    call_policy_patch[key] = value
                if key == LOCK_SCREEN_INFO_KEY:
                    if not isinstance(value, str):
                        raise HTTPException(400, "锁屏监管提示必须是文本")
                    value = value.strip()
                    if len(value) > MAX_LOCK_SCREEN_INFO_LENGTH:
                        raise HTTPException(400, f"锁屏监管提示不能超过 {MAX_LOCK_SCREEN_INFO_LENGTH} 个字符")
                if key == RINGER_PERIODS_KEY:
                    try:
                        value = normalize_ringer_periods(value)
                    except ValueError as exc:
                        raise HTTPException(400, str(exc)) from exc
                item["value"], item["status"], item["updated_at"] = value, "pending", now()
                changed.append(item["key"])
        if install_value is not None:
            updated_at = now()
            for key in ("block_user_install", "block_unknown_sources"):
                item = allowed.get(key)
                if item:
                    item["value"], item["status"], item["updated_at"] = install_value, "pending", updated_at
                    if key not in changed:
                        changed.append(key)
            STATE["basic_policies"].setdefault(device_id, {})["installation_approval_required"] = install_value
        if call_policy_patch:
            policy = STATE["basic_policies"].setdefault(device_id, default_basic_policy())
            policy.update(call_policy_patch)
            canonicalize_call_policy(policy)
            updated_at = now()
            for key in CALL_POLICY_KEYS:
                item = allowed.get(key)
                if item:
                    item["value"], item["status"], item["updated_at"] = policy.get(key), "pending", updated_at
                    if key not in changed:
                        changed.append(key)
        STATE["devices"][device_id]["policy_version"] += 1
        audit("policy.owner.update", device_id, "设备所有者策略已更新，等待设备轮询")
        save_state()
        return {"ok": True, "policy_version": STATE["devices"][device_id]["policy_version"], "status": "pending_device_ack", "changed": changed, "signature": "polling-policy"}


@app.get("/api/v1/devices/{device_id}/basic-policy")
def basic_policy(device_id: str, _: str = Depends(admin_required)) -> dict[str, Any]:
    get_device(device_id)
    return {"ok": True, "policy": STATE["basic_policies"].get(device_id, {})}


@app.put("/api/v1/devices/{device_id}/basic-policy")
def update_basic_policy(device_id: str, input: dict[str, Any], _: str = Depends(admin_required)) -> dict[str, Any]:
    get_device(device_id)
    allowed_keys = {"installation_approval_required", "default_network_mode", "defender_self_protection", "background_protection_enabled", "call_screening_enabled", "call_allowlist", "contacts_only_calls", "suspended_packages"}
    unknown = set(input) - allowed_keys
    if unknown:
        raise HTTPException(400, "基础策略包含未知字段: " + ", ".join(sorted(unknown)))
    normalized: dict[str, Any] = {}
    for key in ("installation_approval_required", "defender_self_protection", "background_protection_enabled", "call_screening_enabled", "contacts_only_calls"):
        if key in input:
            if not isinstance(input[key], bool):
                raise HTTPException(400, f"{key} 必须是布尔值")
            normalized[key] = input[key]
    if "default_network_mode" in input:
        if input["default_network_mode"] not in ("allow_all", "deny_unlisted"):
            raise HTTPException(400, "未知默认联网策略")
        normalized["default_network_mode"] = input["default_network_mode"]
    if "call_allowlist" in input:
        normalized["call_allowlist"] = normalize_call_allowlist(input["call_allowlist"])
    if "suspended_packages" in input:
        packages = input["suspended_packages"]
        if not isinstance(packages, list) or len(packages) > 500:
            raise HTTPException(400, "停用应用列表格式无效")
        cleaned_packages = []
        for package_name in packages:
            value = str(package_name).strip()
            if value == PACKAGE_NAME:
                raise HTTPException(400, "不能停用 3Pon Defender 自身")
            if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.]{0,254}", value):
                raise HTTPException(400, "停用应用列表包含无效包名")
            if value not in cleaned_packages:
                cleaned_packages.append(value)
        normalized["suspended_packages"] = cleaned_packages
    with STATE_LOCK:
        policy = STATE["basic_policies"].setdefault(device_id, {})
        effective_policy = {**default_basic_policy(), **policy, **normalized}
        if effective_policy.get("contacts_only_calls") is True:
            normalized["call_screening_enabled"] = True
        policy.update(normalized)
        mapping = {"installation_approval_required": ("block_user_install", "block_unknown_sources"), "defender_self_protection": ("defender_uninstall_blocked",), "background_protection_enabled": ("defender_background_protection",), "call_screening_enabled": ("call_screening_enabled",), "call_allowlist": ("call_allowlist",), "contacts_only_calls": ("contacts_only_calls",), "default_network_mode": ("network_default_mode",)}
        settings = {item["key"]: item for item in STATE["settings"][device_id]}
        for source, targets in mapping.items():
            if source in normalized:
                for target in targets:
                    if target in settings:
                        settings[target]["value"], settings[target]["status"], settings[target]["updated_at"] = normalized[source], "pending", now()
        STATE["devices"][device_id]["policy_version"] += 1
        audit("policy.basic.update", device_id, "基础控制策略已更新，等待设备轮询")
        save_state()
        return {"ok": True, "policy_version": STATE["devices"][device_id]["policy_version"], "status": "pending_device_ack", "changed": list(normalized), "signature": "polling-policy"}


@app.get("/api/v1/devices/{device_id}/effective-state")
def effective_state(device_id: str, _: str = Depends(admin_required)) -> dict[str, Any]:
    get_device(device_id)
    return {"ok": True, "device_id": device_id, "policy_version": STATE["devices"][device_id].get("policy_version", 1), "settings": STATE["settings"].get(device_id, []), "signature": "polling-policy", "last_apply_status": "等待设备轮询"}


@app.post("/api/v1/devices/{device_id}/owner-policy/validate")
def validate_policy(device_id: str, input: PolicyUpdate, _: str = Depends(admin_required)) -> dict[str, Any]:
    get_device(device_id)
    keys = {x["key"] for x in STATE["settings"].get(device_id, [])}
    return {"ok": True, "valid": all(item.get("key") in keys for item in input.settings), "errors": []}


@app.post("/api/v1/devices/{device_id}/commands")
def create_command(device_id: str, input: Command, _: str = Depends(admin_required)) -> dict[str, Any]:
    get_device(device_id)
    with STATE_LOCK:
        command = {"id": new_id(), "device_id": device_id, "kind": input.kind, "payload": input.payload, "status": "queued", "created_at": now(), "requires_confirmation": input.requires_confirmation}
        STATE["commands"].append(command)
        audit("command.created", device_id, f"已创建命令 {input.kind}")
        save_state()
    return {"ok": True, "command": command, "requires_confirmation": input.requires_confirmation}


@app.get("/api/v1/devices/{device_id}/apps")
def device_apps(device_id: str, _: str = Depends(admin_required)) -> dict[str, Any]:
    device = get_device(device_id)
    catalog = STATE["app_catalog"].get(device_id, empty_app_catalog())
    action_names = {"suspend_app": "suspend", "hide_app": "hide", "network_block": "network_block", "network_allow": "network_allow", "uninstall_app": "uninstall", "set_app_permission": "permission"}
    pending_actions = []
    for command in STATE["commands"]:
        if command.get("device_id") != device_id or command.get("status") not in ("queued", "delivered"):
            continue
        payload = command.get("payload") or {}
        package_name = str(payload.get("package_name", ""))
        action_name = action_names.get(command.get("kind"))
        if package_name and action_name:
            pending_actions.append({"id": command["id"], "package_name": package_name, "action": action_name, "status": command["status"], "created_at": command.get("created_at")})
    return {"ok": True, "device_id": device_id, "revision": catalog.get("revision", ""), "updated_at": catalog.get("updated_at"), "apps": catalog.get("apps", []), "pending_actions": pending_actions, "update_status": device.get("update_status", "idle"), "update_version_code": device.get("update_version_code", 0), "update_message": device.get("update_message"), "update_updated_at": device.get("update_updated_at")}


@app.post("/api/v1/devices/{device_id}/apps/{package_name:path}/action")
def device_app_action(device_id: str, package_name: str, input: AppAction, _: str = Depends(admin_required)) -> dict[str, Any]:
    package_name = package_name.strip()
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.]{0,254}", package_name):
        raise HTTPException(400, "应用包名格式无效")
    if package_name == PACKAGE_NAME:
        raise HTTPException(400, "不能管理 3Pon Defender 自身")
    action_map = {
        "suspend": ("suspend_app", {"package_name": package_name, "suspended": True}),
        "resume": ("suspend_app", {"package_name": package_name, "suspended": False}),
        "hide": ("hide_app", {"package_name": package_name, "hidden": True}),
        "unhide": ("hide_app", {"package_name": package_name, "hidden": False}),
        "network_block": ("network_block", {"package_name": package_name}),
        "network_allow": ("network_allow", {"package_name": package_name}),
        "uninstall": ("uninstall_app", {"package_name": package_name}),
    }
    if input.action not in action_map:
        raise HTTPException(400, "不支持的应用操作")
    kind, payload = action_map[input.action]
    with STATE_LOCK:
        get_device(device_id)
        command = {"id": new_id(), "device_id": device_id, "kind": kind, "payload": payload, "status": "queued", "created_at": now(), "requires_confirmation": input.action in {"uninstall", "network_block"}}
        STATE["commands"].append(command)
        audit("app.action." + input.action, device_id, f"管理员对 {package_name} 请求 {input.action}")
        save_state()
    return {"ok": True, "command": command}


@app.post("/api/v1/devices/{device_id}/apps/{package_name:path}/permission")
def device_app_permission(device_id: str, package_name: str, input: AppPermissionAction, _: str = Depends(admin_required)) -> dict[str, Any]:
    package_name = package_name.strip()
    permission = input.permission.strip()
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.]{0,254}", package_name):
        raise HTTPException(400, "应用包名格式无效")
    if package_name == PACKAGE_NAME:
        raise HTTPException(400, "不能修改 3Pon Defender 自身权限")
    if not re.fullmatch(r"android\.permission\.[A-Z0-9_]+", permission):
        raise HTTPException(400, "仅支持 Android 运行时权限")
    if input.grant_state not in {"default", "granted", "denied"}:
        raise HTTPException(400, "未知权限状态")
    with STATE_LOCK:
        get_device(device_id)
        app_row = next((item for item in STATE["app_catalog"].get(device_id, {}).get("apps", []) if item.get("package_name") == package_name), None)
        detail = next((item for item in (app_row or {}).get("permission_details", []) if item.get("name") == permission), None)
        if not detail or not detail.get("controllable"):
            raise HTTPException(400, "该应用权限不可由 Device Owner 修改")
        command = {"id": new_id(), "device_id": device_id, "kind": "set_app_permission", "payload": {"package_name": package_name, "permission": permission, "grant_state": input.grant_state}, "status": "queued", "created_at": now(), "requires_confirmation": input.grant_state == "denied"}
        STATE["commands"].append(command)
        audit("app.permission." + input.grant_state, device_id, f"管理员将 {package_name} 的 {permission} 设置为 {input.grant_state}")
        save_state()
    return {"ok": True, "command": command}


@app.get("/api/v1/install-requests")
def install_requests(_: str = Depends(admin_required)) -> dict[str, Any]:
    return {"ok": True, "requests": STATE["install_requests"]}


@app.post("/api/v1/install-requests")
def new_install_request(input: dict[str, Any], _: str = Depends(admin_required)) -> dict[str, Any]:
    item = {"id": new_id(), **input, "status": "pending", "requested_at": now()}
    with STATE_LOCK:
        STATE["install_requests"].append(item)
        save_state()
    return {"ok": True, "request": item}


@app.post("/api/v1/install-requests/{request_id}/{decision}")
def decide_install(request_id: str, decision: str, _: str = Depends(admin_required)) -> dict[str, Any]:
    if decision not in ("approve", "reject"):
        raise HTTPException(400, "无效的审批动作")
    with STATE_LOCK:
        item = next((row for row in STATE["install_requests"] if row["id"] == request_id), None)
        if not item:
            raise HTTPException(404, "安装申请不存在")
        item["status"] = "approved_pending_device" if decision == "approve" else "rejected"
        if decision == "approve":
            STATE["commands"].append({"id": new_id(), "device_id": item["device_id"], "kind": "install_approved", "payload": item, "status": "queued", "created_at": now()})
        audit(f"install.{decision}d", request_id, "管理员批准应用安装" if decision == "approve" else "管理员拒绝应用安装")
        save_state()
    return {"ok": True}


@app.get("/api/v1/audit")
def audit_log(_: str = Depends(admin_required)) -> dict[str, Any]:
    return {"ok": True, "events": list(reversed(STATE["audit"][-100:]))}


if WEB_ROOT.is_dir():
    app.mount("/", StaticFiles(directory=WEB_ROOT, html=True), name="web")
