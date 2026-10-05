use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    body::Body,
    extract::ws::{Message, WebSocket},
    extract::{Path, Query, State, WebSocketUpgrade},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base32::{decode, Alphabet};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::HashMap,
    env, fs,
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
};
use tokio::sync::RwLock;
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};
use tracing::info;
use url::Url;
use uuid::Uuid;

type HmacSha1 = Hmac<Sha1>;

#[derive(Clone)]
struct AppState {
    inner: Arc<RwLock<InnerState>>,
}

#[derive(Clone)]
struct InnerState {
    initialized: bool,
    admin_username: String,
    admin_password_hash: String,
    totp_secret: String,
    state_path: PathBuf,
    dev_mode: bool,
    sessions: HashMap<String, DateTime<Utc>>,
    device_tokens: HashMap<Uuid, String>,
    devices: Vec<Device>,
    owner_settings: HashMap<Uuid, Vec<OwnerSetting>>,
    basic_policies: HashMap<Uuid, BasicControlPolicy>,
    install_requests: Vec<InstallRequest>,
    audit: Vec<AuditEvent>,
    commands: Vec<CommandRecord>,
    recovery_keys: Vec<RecoveryKey>,
    pairing_sessions: HashMap<Uuid, PairingSession>,
    policy_signing_key: Arc<SigningKey>,
}

#[derive(Debug, Serialize)]
struct ApiError {
    ok: bool,
    error: String,
}

#[derive(Debug, Clone, Serialize)]
struct Device {
    id: Uuid,
    name: String,
    model: String,
    manufacturer: String,
    android_api: u32,
    hyperos_version: String,
    base_url: String,
    status: String,
    last_seen_at: DateTime<Utc>,
    consent_version: Option<String>,
    consented_at: Option<DateTime<Utc>>,
    policy_version: u64,
}

#[derive(Debug, Clone, Serialize)]
struct DeviceCapabilities {
    device_id: Uuid,
    android_api: u32,
    manufacturer: String,
    model: String,
    hyperos_version: String,
    supported_policies: Vec<PolicyCapability>,
}

#[derive(Debug, Clone, Serialize)]
struct PolicyCapability {
    key: String,
    category: String,
    label: String,
    supported: bool,
    reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum SettingValue {
    Bool(bool),
    Integer(i64),
    Text(String),
    Strings(Vec<String>),
}

#[derive(Debug, Clone, Serialize)]
struct OwnerSetting {
    key: String,
    category: String,
    label: String,
    description: String,
    kind: String,
    value: SettingValue,
    supported: bool,
    high_risk: bool,
    status: String,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SettingPatch {
    key: String,
    value: SettingValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpdateOwnerPolicy {
    settings: Vec<SettingPatch>,
    reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BasicControlPolicy {
    installation_approval_required: bool,
    default_network_mode: String,
    defender_self_protection: bool,
    call_screening_enabled: bool,
    call_allowlist: Vec<String>,
    suspended_packages: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    otp: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    ok: bool,
    token: String,
    user: String,
    demo_mode: bool,
}

#[derive(Debug, Serialize)]
struct AuthStatusResponse {
    ok: bool,
    initialized: bool,
    setup_required: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct SetupRequest {
    username: String,
    password: String,
    totp_secret: String,
    otp: String,
}

#[derive(Debug, Clone, Serialize)]
struct InstallRequest {
    id: Uuid,
    device_id: Uuid,
    package_name: String,
    display_name: String,
    version: String,
    sha256: String,
    permissions: Vec<String>,
    status: String,
    requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
struct NewInstallRequest {
    device_id: Uuid,
    package_name: String,
    display_name: String,
    version: String,
    sha256: String,
    permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct AuditEvent {
    id: Uuid,
    at: DateTime<Utc>,
    event: String,
    target: String,
    message: String,
}

#[derive(Debug, Clone, Serialize)]
struct CommandRecord {
    id: Uuid,
    device_id: Uuid,
    kind: String,
    status: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecoveryKey {
    id: Uuid,
    value: String,
    used: bool,
    used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedAdminState {
    version: u32,
    admin_username: String,
    admin_password_hash: String,
    totp_secret: String,
    recovery_keys: Vec<RecoveryKey>,
}

#[derive(Debug, Clone)]
struct PairingSession {
    pairing_token: String,
    base_url: String,
    device_name: String,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct PairingSessionRequest {
    base_url: String,
    device_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct PairingPayload {
    kind: &'static str,
    version: u32,
    session_id: Uuid,
    pairing_token: String,
    base_url: String,
    server_public_key: String,
    update_manifest_url: String,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct PairingClaimRequest {
    session_id: Uuid,
    pairing_token: String,
    device_name: String,
    package_name: String,
    model: String,
    manufacturer: String,
    android_api: u32,
    hyperos_version: String,
    device_owner: bool,
    consented: bool,
    consent_version: String,
}

#[derive(Debug, Serialize)]
struct PairingClaimResponse {
    ok: bool,
    device_id: Uuid,
    device_token: String,
    base_url: String,
    server_public_key: String,
    update_manifest_url: String,
    consent_version: String,
}

#[derive(Debug, Serialize)]
struct UpdateManifestPayload {
    package_name: String,
    version_code: u64,
    version_name: String,
    apk_url: String,
    sha256: String,
    signer_sha256: String,
    mandatory: bool,
    published_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct UpdateManifest {
    package_name: String,
    version_code: u64,
    version_name: String,
    apk_url: String,
    sha256: String,
    signer_sha256: String,
    manifest_signature: String,
    signed_payload: String,
    mandatory: bool,
    published_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct DeviceRequestQuery {
    device_id: Uuid,
}

#[derive(Debug, Deserialize)]
struct CommandRequest {
    device_id: Uuid,
    kind: String,
    requires_confirmation: bool,
}

#[derive(Debug, Deserialize)]
struct RecoveryResetRequest {
    recovery_key: String,
    username: String,
    password: String,
    totp_secret: String,
}

#[derive(Debug, Serialize)]
struct DashboardResponse {
    ok: bool,
    devices: Vec<Device>,
    pending_install_requests: usize,
    online_devices: usize,
    pending_commands: usize,
}

#[derive(Debug, Serialize)]
struct OwnerPolicyResponse {
    ok: bool,
    device_id: Uuid,
    version: u64,
    settings: Vec<OwnerSetting>,
    signature: String,
}

#[derive(Debug, Serialize)]
struct EffectiveStateResponse {
    ok: bool,
    device_id: Uuid,
    policy_version: u64,
    settings: Vec<OwnerSetting>,
    signature: String,
    last_apply_status: String,
}

#[derive(Debug, Serialize)]
struct UpdateResponse {
    ok: bool,
    policy_version: u64,
    status: String,
    changed: Vec<String>,
    signature: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()))
        .init();

    let state = AppState {
        inner: Arc::new(RwLock::new(seed_state())),
    };

    let public = Router::new()
        .route("/api/health", get(health))
        .route("/api/v1/auth/status", get(auth_status))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/setup", post(setup_admin))
        .route(
            "/api/v1/auth/recovery/reset",
            post(reset_admin_with_recovery_key),
        )
        .route("/api/v1/device/pairing/claim", post(claim_pairing_session))
        .route(
            "/api/v1/device/update-manifest",
            get(device_update_manifest),
        )
        .route(
            "/api/v1/device/update-artifacts/:version",
            get(device_update_artifact),
        );

    let protected = Router::new()
        .route("/api/v1/dashboard", get(dashboard))
        .route("/api/v1/devices", get(list_devices))
        .route("/api/v1/devices/:id/capabilities", get(capabilities))
        .route(
            "/api/v1/devices/:id/basic-policy",
            get(get_basic_policy).put(update_basic_policy),
        )
        .route(
            "/api/v1/devices/:id/owner-policy",
            get(get_owner_policy).put(update_owner_policy),
        )
        .route("/api/v1/devices/:id/effective-state", get(effective_state))
        .route(
            "/api/v1/devices/:id/owner-policy/validate",
            post(validate_owner_policy),
        )
        .route("/api/v1/devices/:id/commands", post(create_command))
        .route(
            "/api/v1/install-requests",
            get(list_install_requests).post(create_install_request),
        )
        .route(
            "/api/v1/install-requests/:id/approve",
            post(approve_install_request),
        )
        .route(
            "/api/v1/install-requests/:id/reject",
            post(reject_install_request),
        )
        .route("/api/v1/auth/recovery-keys", get(recovery_keys))
        .route("/api/v1/pairing/sessions", post(create_pairing_session))
        .route("/api/v1/audit", get(audit_log))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let app = public
        .merge(protected)
        .route("/api/v1/device/ws/:id", get(device_ws))
        .fallback_service(ServeDir::new("../web/dist").append_index_html_on_directories(true))
        .layer(CorsLayer::very_permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let bind = env::var("THREEPON_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let address: SocketAddr = bind.parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    info!(%address, "3Pon Defender server started");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "service": "3pon-defender", "mode": "development-slice" }))
}

async fn auth_status(State(state): State<AppState>) -> Json<AuthStatusResponse> {
    let data = state.inner.read().await;
    Json(AuthStatusResponse {
        ok: true,
        initialized: data.initialized,
        setup_required: !data.initialized,
    })
}

async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    let valid = if let Some(token) = token {
        state.inner.read().await.sessions.contains_key(token)
    } else {
        false
    };

    if valid {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(ApiError {
                ok: false,
                error: "需要管理员登录".to_string(),
            }),
        )
            .into_response()
    }
}

async fn setup_admin(State(state): State<AppState>, Json(input): Json<SetupRequest>) -> Response {
    let username = input.username.trim().to_string();
    let totp_secret = normalize_totp_secret(&input.totp_secret);
    if username.chars().count() < 3
        || username.chars().count() > 64
        || input.password.chars().count() < 9
        || !valid_totp_secret(&totp_secret)
        || !verify_totp(&totp_secret, &input.otp)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                ok: false,
                error: "用户名、密码、TOTP 密钥或验证码不符合要求".to_string(),
            }),
        )
            .into_response();
    }

    let mut data = state.inner.write().await;
    if data.initialized {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "ok": false,
                "error": "管理员已经初始化，请直接登录"
            })),
        )
            .into_response();
    }

    let password_hash = hash_password(&input.password);
    if let Err(error) = persist_admin_state(
        &data.state_path,
        &username,
        &password_hash,
        &totp_secret,
        &data.recovery_keys,
    ) {
        tracing::error!(%error, "failed to persist initial administrator state");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                ok: false,
                error: "管理员初始化失败，无法保存安全配置".to_string(),
            }),
        )
            .into_response();
    }

    data.initialized = true;
    data.admin_username = username.clone();
    data.admin_password_hash = password_hash;
    data.totp_secret = totp_secret;
    let token = Uuid::new_v4().to_string();
    data.sessions.insert(token.clone(), Utc::now());
    data.audit.push(audit(
        "admin.initialized",
        "admin",
        "首次创建管理员账号并启用 TOTP",
    ));
    Json(serde_json::json!({
        "ok": true,
        "status": "initialized",
        "token": token,
        "user": username,
        "demo_mode": data.dev_mode
    }))
    .into_response()
}

async fn login(State(state): State<AppState>, Json(input): Json<LoginRequest>) -> Response {
    let mut data = state.inner.write().await;
    if !data.initialized {
        return (
            StatusCode::PRECONDITION_REQUIRED,
            Json(serde_json::json!({
                "ok": false,
                "setup_required": true,
                "error": "请先完成首次管理员初始化"
            })),
        )
            .into_response();
    }
    let username_valid = input.username == data.admin_username;
    let password_valid = verify_password(&data.admin_password_hash, &input.password);
    let otp_valid = verify_totp(&data.totp_secret, &input.otp);

    if !(username_valid && password_valid && otp_valid) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiError {
                ok: false,
                error: "用户名、密码或 OTP 不正确".to_string(),
            }),
        )
            .into_response();
    }

    let token = Uuid::new_v4().to_string();
    data.sessions.insert(token.clone(), Utc::now());
    data.audit
        .push(audit("admin.login", "admin", "管理员登录成功"));
    Json(LoginResponse {
        ok: true,
        token,
        user: data.admin_username.clone(),
        demo_mode: data.dev_mode,
    })
    .into_response()
}

async fn reset_admin_with_recovery_key(
    State(state): State<AppState>,
    Json(input): Json<RecoveryResetRequest>,
) -> Response {
    let username = input.username.trim().to_string();
    let totp_secret = normalize_totp_secret(&input.totp_secret);
    if username.chars().count() < 3
        || username.chars().count() > 64
        || input.password.chars().count() < 9
        || !valid_totp_secret(&totp_secret)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                ok: false,
                error: "新管理员账号、密码或 TOTP 不符合要求".to_string(),
            }),
        )
            .into_response();
    }
    let mut data = state.inner.write().await;
    if !data.initialized {
        return (
            StatusCode::CONFLICT,
            Json(ApiError {
                ok: false,
                error: "管理员尚未初始化，请先完成首次设置".to_string(),
            }),
        )
            .into_response();
    }

    let mut recovery_keys = data.recovery_keys.clone();
    let key_found = if let Some(key) = recovery_keys
        .iter_mut()
        .find(|key| !key.used && key.value == input.recovery_key)
    {
        key.used = true;
        key.used_at = Some(Utc::now());
        true
    } else {
        false
    };
    if !key_found {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiError {
                ok: false,
                error: "恢复密钥无效或已经使用".to_string(),
            }),
        )
            .into_response();
    }

    let password_hash = hash_password(&input.password);
    if let Err(error) = persist_admin_state(
        &data.state_path,
        &username,
        &password_hash,
        &totp_secret,
        &recovery_keys,
    ) {
        tracing::error!(%error, "failed to persist administrator reset");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                ok: false,
                error: "管理员重置失败，无法保存安全配置".to_string(),
            }),
        )
            .into_response();
    }

    data.admin_username = username;
    data.admin_password_hash = password_hash;
    data.totp_secret = totp_secret;
    data.recovery_keys = recovery_keys;
    data.sessions.clear();
    data.audit.push(audit(
        "admin.recovery.reset",
        "admin",
        "使用一次性恢复密钥重置管理员账号",
    ));
    Json(serde_json::json!({ "ok": true, "status": "credentials_reset", "sessions_revoked": true }))
        .into_response()
}

async fn dashboard(State(state): State<AppState>) -> Json<DashboardResponse> {
    let data = state.inner.read().await;
    Json(DashboardResponse {
        ok: true,
        devices: data.devices.clone(),
        pending_install_requests: data
            .install_requests
            .iter()
            .filter(|item| item.status == "pending")
            .count(),
        online_devices: data
            .devices
            .iter()
            .filter(|item| item.status == "online")
            .count(),
        pending_commands: data
            .commands
            .iter()
            .filter(|item| item.status == "queued")
            .count(),
    })
}

async fn list_devices(State(state): State<AppState>) -> Json<serde_json::Value> {
    let data = state.inner.read().await;
    Json(serde_json::json!({ "ok": true, "devices": data.devices }))
}

async fn capabilities(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    let data = state.inner.read().await;
    let Some(device) = data.devices.iter().find(|device| device.id == id) else {
        return not_found("设备不存在");
    };
    let settings = data.owner_settings.get(&id).cloned().unwrap_or_default();
    let supported_policies = settings
        .iter()
        .map(|setting| PolicyCapability {
            key: setting.key.clone(),
            category: setting.category.clone(),
            label: setting.label.clone(),
            supported: setting.supported,
            reason: if setting.supported {
                None
            } else {
                Some("当前设备或系统版本未提供此公开策略".to_string())
            },
        })
        .collect();
    Json(serde_json::json!({
        "ok": true,
        "capabilities": DeviceCapabilities {
            device_id: id,
            android_api: device.android_api,
            manufacturer: device.manufacturer.clone(),
            model: device.model.clone(),
            hyperos_version: device.hyperos_version.clone(),
            supported_policies,
        }
    }))
    .into_response()
}

async fn get_basic_policy(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    let data = state.inner.read().await;
    match data.basic_policies.get(&id) {
        Some(policy) => Json(serde_json::json!({ "ok": true, "policy": policy })).into_response(),
        None => not_found("设备策略不存在"),
    }
}

async fn update_basic_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(policy): Json<BasicControlPolicy>,
) -> Response {
    let mut data = state.inner.write().await;
    if !data.devices.iter().any(|device| device.id == id) {
        return not_found("设备不存在");
    }
    data.basic_policies.insert(id, policy.clone());
    let mut changed = Vec::new();
    let mappings = [
        (
            "block_user_install",
            SettingValue::Bool(policy.installation_approval_required),
        ),
        (
            "network_default_mode",
            SettingValue::Text(policy.default_network_mode.clone()),
        ),
        (
            "defender_uninstall_blocked",
            SettingValue::Bool(policy.defender_self_protection),
        ),
        (
            "call_screening_enabled",
            SettingValue::Bool(policy.call_screening_enabled),
        ),
        (
            "call_allowlist",
            SettingValue::Strings(policy.call_allowlist.clone()),
        ),
    ];
    if let Some(settings) = data.owner_settings.get_mut(&id) {
        for (key, value) in mappings {
            if let Some(setting) = settings.iter_mut().find(|setting| setting.key == key) {
                setting.value = value;
                setting.status = "pending".to_string();
                setting.updated_at = Utc::now();
                changed.push(key.to_string());
            }
        }
    }
    let version = {
        let device = data
            .devices
            .iter_mut()
            .find(|device| device.id == id)
            .unwrap();
        device.policy_version += 1;
        device.policy_version
    };
    let signature = sign_policy(
        &data.policy_signing_key,
        version,
        data.owner_settings
            .get(&id)
            .cloned()
            .unwrap_or_default()
            .as_slice(),
    );
    data.audit.push(audit(
        "policy.basic.update",
        &id.to_string(),
        "基础控制策略已更新",
    ));
    Json(UpdateResponse {
        ok: true,
        policy_version: version,
        status: "pending_device_ack".to_string(),
        changed,
        signature,
    })
    .into_response()
}

async fn get_owner_policy(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    let data = state.inner.read().await;
    let Some(device) = data.devices.iter().find(|device| device.id == id) else {
        return not_found("设备不存在");
    };
    let settings = data.owner_settings.get(&id).cloned().unwrap_or_default();
    let signature = sign_policy(&data.policy_signing_key, device.policy_version, &settings);
    Json(OwnerPolicyResponse {
        ok: true,
        device_id: id,
        version: device.policy_version,
        settings,
        signature,
    })
    .into_response()
}

async fn validate_owner_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateOwnerPolicy>,
) -> Response {
    let data = state.inner.read().await;
    let Some(settings) = data.owner_settings.get(&id) else {
        return not_found("设备策略不存在");
    };
    let mut warnings = Vec::new();
    for patch in input.settings {
        match settings.iter().find(|setting| setting.key == patch.key) {
            None => warnings.push(format!("未知策略：{}", patch.key)),
            Some(setting) if !setting.supported => {
                warnings.push(format!("设备不支持：{}", setting.label))
            }
            Some(setting) if setting.high_risk => {
                warnings.push(format!("高风险策略需要二次确认：{}", setting.label))
            }
            Some(_) => {}
        }
    }
    Json(serde_json::json!({ "ok": true, "valid": warnings.iter().all(|warning| !warning.starts_with("未知策略")), "warnings": warnings })).into_response()
}

async fn update_owner_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateOwnerPolicy>,
) -> Response {
    let mut data = state.inner.write().await;
    let Some(device_index) = data.devices.iter().position(|device| device.id == id) else {
        return not_found("设备不存在");
    };
    let Some(settings) = data.owner_settings.get_mut(&id) else {
        return not_found("设备策略不存在");
    };
    let mut changed = Vec::new();
    for patch in input.settings {
        if let Some(setting) = settings.iter_mut().find(|setting| setting.key == patch.key) {
            if setting.supported {
                setting.value = patch.value;
                setting.status = "pending".to_string();
                setting.updated_at = Utc::now();
                changed.push(setting.key.clone());
            }
        }
    }
    let version = {
        let device = &mut data.devices[device_index];
        device.policy_version += 1;
        device.policy_version
    };
    let signature = sign_policy(
        &data.policy_signing_key,
        version,
        data.owner_settings
            .get(&id)
            .cloned()
            .unwrap_or_default()
            .as_slice(),
    );
    data.audit.push(audit(
        "policy.owner.update",
        &id.to_string(),
        input.reason.as_deref().unwrap_or("设备所有者策略已更新"),
    ));
    Json(UpdateResponse {
        ok: true,
        policy_version: version,
        status: "pending_device_ack".to_string(),
        changed,
        signature,
    })
    .into_response()
}

async fn effective_state(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    let data = state.inner.read().await;
    let Some(device) = data.devices.iter().find(|device| device.id == id) else {
        return not_found("设备不存在");
    };
    let settings = data.owner_settings.get(&id).cloned().unwrap_or_default();
    let signature = sign_policy(&data.policy_signing_key, device.policy_version, &settings);
    Json(EffectiveStateResponse {
        ok: true,
        device_id: id,
        policy_version: device.policy_version,
        settings,
        signature,
        last_apply_status: "pending_device_ack".to_string(),
    })
    .into_response()
}

async fn create_command(
    State(state): State<AppState>,
    Json(input): Json<CommandRequest>,
) -> Response {
    let mut data = state.inner.write().await;
    if !data
        .devices
        .iter()
        .any(|device| device.id == input.device_id)
    {
        return not_found("设备不存在");
    }
    let command = CommandRecord {
        id: Uuid::new_v4(),
        device_id: input.device_id,
        kind: input.kind.clone(),
        status: "queued".to_string(),
        created_at: Utc::now(),
    };
    data.audit.push(audit(
        "command.created",
        &input.device_id.to_string(),
        &format!("已创建命令 {}", input.kind),
    ));
    data.commands.push(command.clone());
    Json(serde_json::json!({ "ok": true, "command": command, "requires_confirmation": input.requires_confirmation })).into_response()
}

async fn create_pairing_session(
    State(state): State<AppState>,
    Json(input): Json<PairingSessionRequest>,
) -> Response {
    let dev_mode = state.inner.read().await.dev_mode;
    let Ok(base_url) = normalize_base_url(&input.base_url, dev_mode) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                ok: false,
                error: "管理台地址无效；必须使用浏览器当前访问的 HTTP(S) origin".to_string(),
            }),
        )
            .into_response();
    };

    let mut data = state.inner.write().await;
    let session_id = Uuid::new_v4();
    let pairing_token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + chrono::Duration::minutes(10);
    let device_name = input.device_name.unwrap_or_else(|| "长辈手机".to_string());
    let server_public_key = BASE64.encode(data.policy_signing_key.verifying_key().to_bytes());
    let update_manifest_url = format!("{base_url}/api/v1/device/update-manifest");
    let payload = PairingPayload {
        kind: "3pon_pairing",
        version: 1,
        session_id,
        pairing_token: pairing_token.clone(),
        base_url: base_url.clone(),
        server_public_key: server_public_key.clone(),
        update_manifest_url: update_manifest_url.clone(),
        expires_at,
    };
    let qr_payload =
        serde_json::to_string(&payload).expect("pairing payload serialization should work");
    data.pairing_sessions.insert(
        session_id,
        PairingSession {
            pairing_token,
            base_url: base_url.clone(),
            device_name,
            expires_at,
        },
    );
    data.audit.push(audit(
        "device.pairing.created",
        &session_id.to_string(),
        "管理员创建一次性扫码配对会话",
    ));
    Json(serde_json::json!({
        "ok": true,
        "session_id": session_id,
        "base_url": base_url,
        "server_public_key": server_public_key,
        "update_manifest_url": update_manifest_url,
        "expires_at": expires_at,
        "qr_payload": qr_payload,
    }))
    .into_response()
}

async fn claim_pairing_session(
    State(state): State<AppState>,
    Json(input): Json<PairingClaimRequest>,
) -> Response {
    if !input.consented {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                ok: false,
                error: "必须先在被管控端明确同意功能和隐私说明".to_string(),
            }),
        )
            .into_response();
    }
    if !input.device_owner {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                ok: false,
                error: "被管控端必须先完成 Device Owner 注册".to_string(),
            }),
        )
            .into_response();
    }
    if input.package_name != "com.threepon.defender" || input.consent_version.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                ok: false,
                error: "被管控端身份或同意版本无效".to_string(),
            }),
        )
            .into_response();
    }

    let mut data = state.inner.write().await;
    let now = Utc::now();
    let Some(session) = data.pairing_sessions.get(&input.session_id).cloned() else {
        return (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                ok: false,
                error: "配对二维码不存在或已经使用".to_string(),
            }),
        )
            .into_response();
    };
    if session.expires_at <= now {
        data.pairing_sessions.remove(&input.session_id);
        return (
            StatusCode::GONE,
            Json(ApiError {
                ok: false,
                error: "配对二维码已过期，请在管控端重新生成".to_string(),
            }),
        )
            .into_response();
    }
    if session.pairing_token != input.pairing_token {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiError {
                ok: false,
                error: "配对二维码凭据无效".to_string(),
            }),
        )
            .into_response();
    }
    data.pairing_sessions.remove(&input.session_id);

    let device_id = Uuid::new_v4();
    let device_token = Uuid::new_v4().to_string();
    let device_name = if input.device_name.trim().is_empty() {
        session.device_name
    } else {
        input.device_name.trim().to_string()
    };
    let settings = default_owner_settings();
    let basic = default_basic_policy();
    let server_public_key = BASE64.encode(data.policy_signing_key.verifying_key().to_bytes());
    let update_manifest_url = format!("{}/api/v1/device/update-manifest", session.base_url);
    data.device_tokens.insert(device_id, device_token.clone());
    data.devices.push(Device {
        id: device_id,
        name: device_name,
        model: input.model,
        manufacturer: input.manufacturer,
        android_api: input.android_api,
        hyperos_version: input.hyperos_version,
        base_url: session.base_url.clone(),
        status: "online".to_string(),
        last_seen_at: now,
        consent_version: Some(input.consent_version.clone()),
        consented_at: Some(now),
        policy_version: 1,
    });
    data.owner_settings.insert(device_id, settings);
    data.basic_policies.insert(device_id, basic);
    data.audit.push(audit(
        "device.pairing.claimed",
        &device_id.to_string(),
        "被管控端在明确同意后完成扫码配对",
    ));
    Json(PairingClaimResponse {
        ok: true,
        device_id,
        device_token,
        base_url: session.base_url,
        server_public_key,
        update_manifest_url,
        consent_version: input.consent_version,
    })
    .into_response()
}

async fn device_update_manifest(
    headers: HeaderMap,
    Query(query): Query<DeviceRequestQuery>,
    State(state): State<AppState>,
) -> Response {
    if !device_authorized(&state, &headers, query.device_id).await {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiError {
                ok: false,
                error: "设备凭据无效".to_string(),
            }),
        )
            .into_response();
    }

    let base_url = {
        let data = state.inner.read().await;
        let Some(device) = data
            .devices
            .iter()
            .find(|device| device.id == query.device_id)
        else {
            return not_found("设备不存在");
        };
        device.base_url.clone()
    };
    let version_code = env::var("THREEPON_UPDATE_VERSION_CODE")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1);
    let version_name =
        env::var("THREEPON_UPDATE_VERSION_NAME").unwrap_or_else(|_| "0.1.0".to_string());
    let artifact_path = env::var("THREEPON_UPDATE_APK_PATH").ok();
    let sha256 = match artifact_path.as_deref() {
        Some(path) => match tokio::fs::read(path).await {
            Ok(bytes) => hex_sha256(&bytes),
            Err(error) => {
                tracing::warn!(%error, path, "update artifact cannot be read");
                String::new()
            }
        },
        None => String::new(),
    };
    let signer_sha256 = env::var("THREEPON_ANDROID_SIGNER_SHA256")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let published_at = Utc::now();
    let apk_url = format!(
        "{base_url}/api/v1/device/update-artifacts/{version_code}?device_id={}",
        query.device_id
    );
    let payload = UpdateManifestPayload {
        package_name: "com.threepon.defender".to_string(),
        version_code,
        version_name,
        apk_url,
        sha256,
        signer_sha256,
        mandatory: env::var("THREEPON_UPDATE_MANDATORY")
            .map(|value| value == "true")
            .unwrap_or(false),
        published_at,
    };
    let signed_payload =
        serde_json::to_vec(&payload).expect("update manifest serialization should work");
    let manifest_signature = {
        let data = state.inner.read().await;
        BASE64.encode(data.policy_signing_key.sign(&signed_payload).to_bytes())
    };
    Json(UpdateManifest {
        package_name: payload.package_name,
        version_code: payload.version_code,
        version_name: payload.version_name,
        apk_url: payload.apk_url,
        sha256: payload.sha256,
        signer_sha256: payload.signer_sha256,
        manifest_signature,
        signed_payload: BASE64.encode(signed_payload),
        mandatory: payload.mandatory,
        published_at: payload.published_at,
    })
    .into_response()
}

async fn device_update_artifact(
    headers: HeaderMap,
    Query(query): Query<DeviceRequestQuery>,
    Path(version): Path<u64>,
    State(state): State<AppState>,
) -> Response {
    if !device_authorized(&state, &headers, query.device_id).await {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiError {
                ok: false,
                error: "设备凭据无效".to_string(),
            }),
        )
            .into_response();
    }
    let expected_version = env::var("THREEPON_UPDATE_VERSION_CODE")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1);
    if version != expected_version {
        return not_found("更新版本不存在");
    }
    let Some(path) = env::var("THREEPON_UPDATE_APK_PATH").ok() else {
        return (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                ok: false,
                error: "管控端尚未发布 APK 更新包".to_string(),
            }),
        )
            .into_response();
    };
    let bytes = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::error!(%error, path, "update artifact read failed");
            return (
                StatusCode::NOT_FOUND,
                Json(ApiError {
                    ok: false,
                    error: "更新包不可读取".to_string(),
                }),
            )
                .into_response();
        }
    };
    let mut response = Response::new(Body::from(bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.android.package-archive"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=threepon-defender.apk"),
    );
    response
}

async fn list_install_requests(State(state): State<AppState>) -> Json<serde_json::Value> {
    let data = state.inner.read().await;
    Json(serde_json::json!({ "ok": true, "requests": data.install_requests }))
}

async fn create_install_request(
    State(state): State<AppState>,
    Json(input): Json<NewInstallRequest>,
) -> Response {
    let mut data = state.inner.write().await;
    if !data
        .devices
        .iter()
        .any(|device| device.id == input.device_id)
    {
        return not_found("设备不存在");
    }
    let request = InstallRequest {
        id: Uuid::new_v4(),
        device_id: input.device_id,
        package_name: input.package_name,
        display_name: input.display_name,
        version: input.version,
        sha256: input.sha256,
        permissions: input.permissions,
        status: "pending".to_string(),
        requested_at: Utc::now(),
    };
    data.audit.push(audit(
        "install.requested",
        &request.package_name,
        "收到新的应用安装申请",
    ));
    data.install_requests.push(request.clone());
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "ok": true, "request": request })),
    )
        .into_response()
}

async fn approve_install_request(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    let mut data = state.inner.write().await;
    let (device_id, package_name, status) = {
        let Some(request) = data
            .install_requests
            .iter_mut()
            .find(|request| request.id == id)
        else {
            return not_found("安装申请不存在");
        };
        request.status = "approved_pending_device".to_string();
        (
            request.device_id,
            request.package_name.clone(),
            request.status.clone(),
        )
    };
    data.commands.push(CommandRecord {
        id: Uuid::new_v4(),
        device_id,
        kind: format!("install:{package_name}"),
        status: "queued".to_string(),
        created_at: Utc::now(),
    });
    data.audit.push(audit(
        "install.approved",
        &package_name,
        "管理员批准应用安装",
    ));
    Json(serde_json::json!({ "ok": true, "status": status })).into_response()
}

async fn reject_install_request(State(state): State<AppState>, Path(id): Path<Uuid>) -> Response {
    let mut data = state.inner.write().await;
    let (package_name, status) = {
        let Some(request) = data
            .install_requests
            .iter_mut()
            .find(|request| request.id == id)
        else {
            return not_found("安装申请不存在");
        };
        request.status = "rejected".to_string();
        (request.package_name.clone(), request.status.clone())
    };
    data.audit.push(audit(
        "install.rejected",
        &package_name,
        "管理员拒绝应用安装",
    ));
    Json(serde_json::json!({ "ok": true, "status": status })).into_response()
}

async fn recovery_keys(State(state): State<AppState>) -> Json<serde_json::Value> {
    let data = state.inner.read().await;
    Json(serde_json::json!({ "ok": true, "keys": data.recovery_keys }))
}

async fn audit_log(State(state): State<AppState>) -> Json<serde_json::Value> {
    let data = state.inner.read().await;
    Json(
        serde_json::json!({ "ok": true, "events": data.audit.iter().rev().take(100).cloned().collect::<Vec<_>>() }),
    )
}

async fn device_ws(
    headers: HeaderMap,
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Response {
    if !device_authorized(&state, &headers, id).await {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiError {
                ok: false,
                error: "设备凭据无效".to_string(),
            }),
        )
            .into_response();
    }
    ws.on_upgrade(move |socket| device_socket(socket, state, id))
}

async fn device_authorized(state: &AppState, headers: &HeaderMap, device_id: Uuid) -> bool {
    let data = state.inner.read().await;
    let token = headers
        .get("x-device-token")
        .and_then(|value| value.to_str().ok());
    data.dev_mode
        || data
            .device_tokens
            .get(&device_id)
            .map(|expected| Some(expected.as_str()) == token)
            .unwrap_or(false)
}

fn normalize_base_url(raw: &str, dev_mode: bool) -> Result<String, ()> {
    let parsed = Url::parse(raw.trim()).map_err(|_| ())?;
    let scheme_allowed = parsed.scheme() == "https" || (dev_mode && parsed.scheme() == "http");
    if !scheme_allowed
        || parsed.host_str().is_none()
        || parsed.username() != ""
        || parsed.password().is_some()
    {
        return Err(());
    }
    if parsed.path() != "" && parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(());
    }
    Ok(parsed
        .origin()
        .ascii_serialization()
        .trim_end_matches('/')
        .to_string())
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn default_seed_base_url(dev_mode: bool) -> String {
    let fallback = if dev_mode {
        "http://localhost:8080"
    } else {
        "https://control.example.com"
    };
    env::var("THREEPON_PUBLIC_BASE_URL")
        .ok()
        .and_then(|value| normalize_base_url(&value, dev_mode).ok())
        .unwrap_or_else(|| fallback.to_string())
}

fn load_policy_signing_key() -> Arc<SigningKey> {
    if let Ok(encoded) = env::var("THREEPON_POLICY_SIGNING_KEY") {
        if let Ok(bytes) = BASE64.decode(encoded.trim()) {
            if bytes.len() == 32 {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&bytes);
                return Arc::new(SigningKey::from_bytes(&seed));
            }
        }
        tracing::warn!("THREEPON_POLICY_SIGNING_KEY is not a valid base64-encoded 32-byte seed; generating a development key");
    }
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    Arc::new(SigningKey::from_bytes(&seed))
}

async fn device_socket(mut socket: WebSocket, state: AppState, id: Uuid) {
    let capabilities = {
        let data = state.inner.read().await;
        let device = data.devices.iter().find(|device| device.id == id);
        let settings = data.owner_settings.get(&id).cloned().unwrap_or_default();
        serde_json::json!({
            "type": "hello_ack",
            "device_id": id,
            "device": device,
            "server_public_key": BASE64.encode(data.policy_signing_key.verifying_key().to_bytes()),
            "capabilities": settings.iter().map(|setting| serde_json::json!({"key": setting.key, "supported": setting.supported})).collect::<Vec<_>>()
        })
    };
    let _ = socket.send(Message::Text(capabilities.to_string())).await;
    while let Some(Ok(message)) = socket.recv().await {
        match message {
            Message::Text(text) => {
                let response = serde_json::json!({ "type": "ack", "received": text.to_string(), "at": Utc::now() });
                if socket
                    .send(Message::Text(response.to_string()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
}

fn load_persisted_admin_state(path: &FsPath) -> Option<PersistedAdminState> {
    match fs::read(path) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(state) => Some(state),
            Err(error) => {
                tracing::warn!(%error, path = %path.display(), "administrator state is invalid; setup is required again");
                None
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            tracing::warn!(%error, path = %path.display(), "administrator state cannot be read; setup is required");
            None
        }
    }
}

fn persist_admin_state(
    path: &FsPath,
    username: &str,
    password_hash: &str,
    totp_secret: &str,
    recovery_keys: &[RecoveryKey],
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let snapshot = PersistedAdminState {
        version: 1,
        admin_username: username.to_string(),
        admin_password_hash: password_hash.to_string(),
        totp_secret: totp_secret.to_string(),
        recovery_keys: recovery_keys.to_vec(),
    };
    let bytes = serde_json::to_vec_pretty(&snapshot).map_err(std::io::Error::other)?;
    let temporary_path = path.with_extension("tmp");
    fs::write(&temporary_path, bytes)?;
    #[cfg(unix)]
    fs::set_permissions(&temporary_path, fs::Permissions::from_mode(0o600))?;
    fs::rename(temporary_path, path)?;
    Ok(())
}

fn generate_recovery_keys() -> Vec<RecoveryKey> {
    (0..8)
        .map(|_| RecoveryKey {
            id: Uuid::new_v4(),
            value: format_recovery_key(),
            used: false,
            used_at: None,
        })
        .collect()
}

fn seed_state() -> InnerState {
    let device_id = Uuid::parse_str("9c6f9d0e-1c68-4a88-8e55-5e0f9e3a1401").unwrap();
    let now = Utc::now();
    let dev_mode = env::var("THREEPON_DEV_MODE").unwrap_or_else(|_| "true".to_string()) != "false";
    let state_path = PathBuf::from(
        env::var("THREEPON_STATE_PATH")
            .unwrap_or_else(|_| "/srv/threepon/data/admin-state.json".to_string()),
    );
    let persisted = load_persisted_admin_state(&state_path);
    let (initialized, admin_username, admin_password_hash, totp_secret, recovery_keys) =
        match persisted {
            Some(state) => (
                true,
                state.admin_username,
                state.admin_password_hash,
                state.totp_secret,
                state.recovery_keys,
            ),
            None => (
                false,
                String::new(),
                String::new(),
                String::new(),
                generate_recovery_keys(),
            ),
        };
    let policy_signing_key = load_policy_signing_key();
    let settings = default_owner_settings();
    let basic = BasicControlPolicy {
        installation_approval_required: true,
        default_network_mode: "deny_unlisted".to_string(),
        defender_self_protection: true,
        call_screening_enabled: true,
        call_allowlist: vec!["110".to_string(), "120".to_string(), "119".to_string()],
        suspended_packages: vec![],
    };
    let audit_events = vec![audit(
        "system.ready",
        &device_id.to_string(),
        if initialized {
            "控制服务已加载，管理员配置已恢复"
        } else {
            "控制服务已启动，等待首次管理员初始化"
        },
    )];
    let mut owner_settings = HashMap::new();
    owner_settings.insert(device_id, settings);
    let mut basic_policies = HashMap::new();
    basic_policies.insert(device_id, basic);
    InnerState {
        initialized,
        admin_username,
        admin_password_hash,
        totp_secret,
        state_path,
        dev_mode,
        sessions: HashMap::new(),
        device_tokens: HashMap::from([(device_id, "dev-device-token".to_string())]),
        devices: vec![Device {
            id: device_id,
            name: "长辈手机 · Xiaomi 14".to_string(),
            model: "Xiaomi 14".to_string(),
            manufacturer: "Xiaomi".to_string(),
            android_api: 36,
            hyperos_version: "HyperOS 3/4 · capability probe".to_string(),
            base_url: default_seed_base_url(dev_mode),
            status: "online".to_string(),
            last_seen_at: now,
            consent_version: Some("2026-09-13".to_string()),
            consented_at: Some(now),
            policy_version: 1,
        }],
        owner_settings,
        basic_policies,
        install_requests: vec![InstallRequest {
            id: Uuid::new_v4(),
            device_id,
            package_name: "com.example.familyclock".to_string(),
            display_name: "家庭时钟".to_string(),
            version: "2.4.1".to_string(),
            sha256: "9c1a3f...d82e".to_string(),
            permissions: vec!["通知".to_string(), "网络".to_string()],
            status: "pending".to_string(),
            requested_at: now,
        }],
        audit: audit_events,
        commands: Vec::new(),
        recovery_keys,
        pairing_sessions: HashMap::new(),
        policy_signing_key,
    }
}

fn default_owner_settings() -> Vec<OwnerSetting> {
    vec![
        owner_setting(
            "block_user_install",
            "应用管理",
            "禁止用户安装应用",
            "阻止浏览器、文件管理器和应用商店直接安装。",
            "boolean",
            SettingValue::Bool(true),
            true,
            true,
        ),
        owner_setting(
            "block_unknown_sources",
            "应用管理",
            "禁止未知来源",
            "关闭未知来源 APK 安装入口。",
            "boolean",
            SettingValue::Bool(true),
            true,
            false,
        ),
        owner_setting(
            "defender_uninstall_blocked",
            "应用管理",
            "3Pon Defender 防卸载",
            "阻止被管控端卸载本软件。",
            "boolean",
            SettingValue::Bool(true),
            true,
            true,
        ),
        owner_setting(
            "suspend_unapproved_apps",
            "应用管理",
            "暂停未批准应用",
            "将未进入审批清单的应用置为暂停状态。",
            "boolean",
            SettingValue::Bool(true),
            true,
            true,
        ),
        owner_setting(
            "restrict_account_changes",
            "用户限制",
            "限制账号变更",
            "限制用户自行添加或删除系统账号。",
            "boolean",
            SettingValue::Bool(false),
            true,
            true,
        ),
        owner_setting(
            "restrict_usb_debugging",
            "用户限制",
            "限制 USB 调试",
            "完成 ADB 注册后关闭调试入口。",
            "boolean",
            SettingValue::Bool(true),
            true,
            true,
        ),
        owner_setting(
            "restrict_developer_options",
            "用户限制",
            "限制开发者选项",
            "限制用户打开开发者选项。",
            "boolean",
            SettingValue::Bool(true),
            true,
            true,
        ),
        owner_setting(
            "camera_disabled",
            "硬件与隐私",
            "禁用摄像头",
            "禁用设备摄像头。",
            "boolean",
            SettingValue::Bool(false),
            true,
            true,
        ),
        owner_setting(
            "microphone_disabled",
            "硬件与隐私",
            "禁用麦克风",
            "公开 Device Owner API 不提供通用麦克风禁用策略。",
            "boolean",
            SettingValue::Bool(false),
            false,
            true,
        ),
        owner_setting(
            "screen_capture_disabled",
            "硬件与隐私",
            "禁止截屏录屏",
            "阻止系统截屏和录屏。",
            "boolean",
            SettingValue::Bool(true),
            true,
            true,
        ),
        owner_setting(
            "status_bar_disabled",
            "系统界面",
            "限制状态栏",
            "隐藏或限制状态栏操作。",
            "boolean",
            SettingValue::Bool(false),
            true,
            true,
        ),
        owner_setting(
            "lock_task_mode",
            "系统界面",
            "Lock Task 模式",
            "将设备锁定在受控应用集合中。",
            "boolean",
            SettingValue::Bool(false),
            true,
            true,
        ),
        owner_setting(
            "always_on_vpn",
            "网络",
            "Always-on VPN",
            "设备启动后自动连接本地 VPN 服务。",
            "boolean",
            SettingValue::Bool(true),
            true,
            true,
        ),
        owner_setting(
            "vpn_lockdown",
            "网络",
            "VPN Lockdown",
            "VPN 断开时阻止应用绕过管控联网。",
            "boolean",
            SettingValue::Bool(true),
            true,
            true,
        ),
        owner_setting(
            "network_default_mode",
            "网络",
            "默认联网策略",
            "未明确允许的应用默认阻断。",
            "text",
            SettingValue::Text("deny_unlisted".to_string()),
            true,
            true,
        ),
        owner_setting(
            "factory_reset_blocked",
            "设备生命周期",
            "限制系统恢复出厂",
            "限制系统界面发起的恢复出厂操作。",
            "boolean",
            SettingValue::Bool(true),
            true,
            true,
        ),
        owner_setting(
            "auto_time_enabled",
            "设备生命周期",
            "自动设置时间",
            "使用网络或系统自动设置时间。",
            "boolean",
            SettingValue::Bool(true),
            true,
            false,
        ),
        owner_setting(
            "external_storage_disabled",
            "设备生命周期",
            "限制外部存储",
            "限制外部存储访问。",
            "boolean",
            SettingValue::Bool(false),
            true,
            true,
        ),
        owner_setting(
            "password_min_length",
            "锁屏与安全",
            "最小密码长度",
            "设备锁屏密码的最小长度。",
            "integer",
            SettingValue::Integer(6),
            true,
            true,
        ),
        owner_setting(
            "keyguard_features_restricted",
            "锁屏与安全",
            "限制锁屏快捷能力",
            "限制锁屏状态下的快捷操作。",
            "boolean",
            SettingValue::Bool(false),
            true,
            true,
        ),
        owner_setting(
            "call_screening_enabled",
            "电话",
            "启用电话筛选",
            "启用电话白名单筛选服务。",
            "boolean",
            SettingValue::Bool(true),
            true,
            true,
        ),
        owner_setting(
            "call_allowlist",
            "电话",
            "电话白名单",
            "允许的联系人号码列表。",
            "string_list",
            SettingValue::Strings(vec![
                "110".to_string(),
                "120".to_string(),
                "119".to_string(),
            ]),
            true,
            true,
        ),
    ]
}

fn default_basic_policy() -> BasicControlPolicy {
    BasicControlPolicy {
        installation_approval_required: true,
        default_network_mode: "deny_unlisted".to_string(),
        defender_self_protection: true,
        call_screening_enabled: true,
        call_allowlist: vec!["110".to_string(), "120".to_string(), "119".to_string()],
        suspended_packages: vec![],
    }
}

#[allow(clippy::too_many_arguments)]
fn owner_setting(
    key: &str,
    category: &str,
    label: &str,
    description: &str,
    kind: &str,
    value: SettingValue,
    supported: bool,
    high_risk: bool,
) -> OwnerSetting {
    OwnerSetting {
        key: key.to_string(),
        category: category.to_string(),
        label: label.to_string(),
        description: description.to_string(),
        kind: kind.to_string(),
        value,
        supported,
        high_risk,
        status: "applied".to_string(),
        updated_at: Utc::now(),
    }
}

fn audit(event: &str, target: &str, message: &str) -> AuditEvent {
    AuditEvent {
        id: Uuid::new_v4(),
        at: Utc::now(),
        event: event.to_string(),
        target: target.to_string(),
        message: message.to_string(),
    }
}

fn sign_policy(key: &SigningKey, version: u64, settings: &[OwnerSetting]) -> String {
    let payload =
        serde_json::to_vec(&(version, settings)).expect("policy serialization should work");
    BASE64.encode(key.sign(&payload).to_bytes())
}

fn not_found(message: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ApiError {
            ok: false,
            error: message.to_string(),
        }),
    )
        .into_response()
}

fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("password hashing should work")
        .to_string()
}

fn verify_password(hash: &str, password: &str) -> bool {
    PasswordHash::new(hash)
        .map(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
        .unwrap_or(false)
}

fn normalize_totp_secret(secret: &str) -> String {
    secret
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase()
}

fn valid_totp_secret(secret: &str) -> bool {
    decode(Alphabet::Rfc4648 { padding: false }, secret)
        .map(|bytes| bytes.len() >= 10)
        .unwrap_or(false)
}

fn verify_totp(secret: &str, code: &str) -> bool {
    if code.len() != 6 || !code.chars().all(|char| char.is_ascii_digit()) {
        return false;
    }
    let Some(secret) = decode(Alphabet::Rfc4648 { padding: false }, secret) else {
        return false;
    };
    let counter = Utc::now().timestamp() / 30;
    (-1..=1).any(|offset| {
        let value = counter + offset;
        if value < 0 {
            return false;
        }
        let Ok(mut mac) = HmacSha1::new_from_slice(&secret) else {
            return false;
        };
        mac.update(&(value as u64).to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let index = (digest[19] & 0x0f) as usize;
        let binary = ((u32::from(digest[index]) & 0x7f) << 24)
            | (u32::from(digest[index + 1]) << 16)
            | (u32::from(digest[index + 2]) << 8)
            | u32::from(digest[index + 3]);
        format!("{:06}", binary % 1_000_000) == code
    })
}

fn format_recovery_key() -> String {
    let mut bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut bytes);
    let digest = Sha256::digest(bytes);
    digest[..12]
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<Vec<_>>()
        .join("")
}

#[cfg(test)]
mod tests {
    use super::normalize_base_url;

    #[test]
    fn normalizes_browser_origin_and_keeps_port() {
        assert_eq!(
            normalize_base_url("http://192.168.1.20:5173/", true).unwrap(),
            "http://192.168.1.20:5173"
        );
        assert_eq!(
            normalize_base_url("https://control.example.com:8443", false).unwrap(),
            "https://control.example.com:8443"
        );
    }

    #[test]
    fn rejects_unsafe_or_non_origin_addresses() {
        assert!(normalize_base_url("http://control.example.com", false).is_err());
        assert!(normalize_base_url("https://control.example.com/admin", false).is_err());
        assert!(normalize_base_url("https://user:password@control.example.com", false).is_err());
        assert!(normalize_base_url("https://control.example.com?next=/", false).is_err());
    }
}
