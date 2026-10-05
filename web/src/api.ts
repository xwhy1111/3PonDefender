import type { AuditEvent, BasicPolicy, CallRuntimeStatus, Dashboard, Device, DeviceApps, InstallRequest, ManagedApp, OwnerSetting, PairingSession, RecoveryKey, SettingValue } from "./types";

const mockDevice: Device = {
  id: "9c6f9d0e-1c68-4a88-8e55-5e0f9e3a1401",
  name: "长辈手机 · Xiaomi 14",
  model: "Xiaomi 14",
  manufacturer: "Xiaomi",
  android_api: 36,
  hyperos_version: "HyperOS 3/4 · capability probe",
  status: "online",
  last_seen_at: new Date().toISOString(),
  consented_at: new Date().toISOString(),
  policy_version: 1,
};

const mockSettings: OwnerSetting[] = [
  ["block_user_install", "应用管理", "禁止用户安装应用", "阻止浏览器、文件管理器和应用商店直接安装。", true, true],
  ["block_unknown_sources", "应用管理", "禁止未知来源", "关闭未知来源 APK 安装入口。", true, false],
  ["defender_uninstall_blocked", "应用管理", "3Pon Defender 防卸载", "阻止被管控端卸载本软件。", true, true],
  ["suspend_unapproved_apps", "应用管理", "暂停未批准应用", "将未进入审批清单的应用置为暂停状态。", true, true],
  ["restrict_account_changes", "用户限制", "限制账号变更", "限制用户自行添加或删除系统账号。", false, true],
  ["restrict_usb_debugging", "用户限制", "限制 USB 调试", "完成 ADB 注册后关闭调试入口。", true, true],
  ["restrict_developer_options", "用户限制", "限制开发者选项", "限制用户打开开发者选项。", true, true],
  ["camera_disabled", "硬件与隐私", "禁用摄像头", "禁用设备摄像头。", false, true],
  ["microphone_disabled", "硬件与隐私", "禁用麦克风", "禁用设备麦克风。", false, true],
  ["screen_capture_disabled", "硬件与隐私", "禁止截屏录屏", "阻止系统截屏和录屏。", true, true],
  ["status_bar_disabled", "系统界面", "限制状态栏", "隐藏或限制状态栏操作。", false, true],
  ["lock_task_mode", "系统界面", "Lock Task 模式", "将设备锁定在受控应用集合中。", false, true],
  ["always_on_vpn", "网络", "Always-on VPN", "设备启动后自动连接本地 VPN 服务。", true, true],
  ["vpn_lockdown", "网络", "VPN Lockdown", "VPN 断开时阻止应用绕过管控联网。", true, true],
  ["factory_reset_blocked", "设备生命周期", "限制系统恢复出厂", "限制系统界面发起的恢复出厂操作。", true, true],
  ["auto_time_enabled", "设备生命周期", "自动设置时间", "使用网络或系统自动设置时间。", true, false],
  ["auto_time_zone_enabled", "设备生命周期", "自动设置时区", "使用网络自动设置设备时区。", true, false],
  ["external_storage_disabled", "设备生命周期", "限制外部存储", "限制外部存储访问。", false, true],
  ["time_zone", "网络与系统", "设置时区", "使用 Android Device Owner 公开接口设置设备时区。", "Asia/Shanghai", true],
  ["stay_awake_while_plugged_in", "网络与系统", "充电时保持唤醒", "设置插电时保持唤醒的电源类型位掩码。", 0, true],
  ["screen_brightness", "系统设置", "屏幕亮度", "设置系统亮度，范围 1 到 255。", 128, false],
  ["screen_brightness_mode", "系统设置", "自动亮度", "在自动亮度和手动亮度之间切换。", "manual", false],
  ["screen_off_timeout_ms", "系统设置", "自动息屏", "设置无操作后自动关闭屏幕的等待时间。", 60000, false],
  ["force_audible_ringer", "系统设置", "强制来电响铃", "禁止切换为静音或仅震动，并保持来电铃声音量最大；媒体和闹铃音量不受影响。", false, false],
  ["force_audible_ringer_periods", "系统设置", "禁止静音时段", "按设备本地时间执行；空列表表示全天，支持跨午夜时段。", [], false],
  ["password_min_length", "锁屏与安全", "最小密码长度", "设备锁屏密码的最小长度。", 6, true],
  ["device_owner_lock_screen_info", "锁屏与安全", "锁屏监管提示", "自定义设备锁屏上显示的监管信息，留空可清除。", "此设备由三胖监管", false],
  ["keyguard_features_restricted", "锁屏与安全", "限制锁屏快捷能力", "限制锁屏状态下的快捷操作。", false, true],
  ["call_screening_enabled", "电话", "启用电话筛选", "启用电话白名单筛选服务。", true, true],
  ["call_allowlist", "电话", "电话白名单", "允许的联系人号码列表。", ["110", "120", "119"], true],
  ["contacts_only_calls", "电话", "仅允许通讯录来电", "仅允许紧急号码、电话白名单和设备通讯录中的号码呼入。", false, true],
].map(([key, category, label, description, value, highRisk]) => ({
  key: key as string,
  category: category as string,
  label: label as string,
  description: description as string,
  kind: Array.isArray(value) ? "string_list" : typeof value === "number" ? "integer" : typeof value,
  value: value as SettingValue,
  supported: true,
  high_risk: highRisk as boolean,
  status: "applied",
  updated_at: new Date().toISOString(),
}));

let mockBasic: BasicPolicy = {
  installation_approval_required: true,
  default_network_mode: "deny_unlisted",
  defender_self_protection: true,
  background_protection_enabled: true,
  call_screening_enabled: true,
  call_allowlist: ["110", "120", "119"],
  contacts_only_calls: false,
  suspended_packages: [],
};

let mockRequests: InstallRequest[] = [{
  id: "4dd2d5f7-3d6d-4f79-913e-7bd47b1c2a40",
  device_id: mockDevice.id,
  package_name: "com.example.familyclock",
  display_name: "家庭时钟",
  version: "2.4.1",
  sha256: "9c1a3f...d82e",
  permissions: ["通知", "网络"],
  status: "pending",
  requested_at: new Date().toISOString(),
}];

let mockApps: ManagedApp[] = [
  { package_name: "com.threepon.defender", label: "3Pon Defender", version_name: "0.1.21", version_code: 22, target_sdk: 36, uid: 10123, system_app: false, enabled: true, suspended: false, hidden: false, network_blocked: false, installer: "adb", signer_sha256: "f8637cc0a3624d9c6e0be485f3c28ece43f856186de7b5442bccc617dcaf3c1f", permissions: ["android.permission.CAMERA", "android.permission.READ_CONTACTS"], permission_details: [{ name: "android.permission.CAMERA", label: "相机", runtime: true, controllable: false, granted: true, grant_state: "default" }, { name: "android.permission.READ_CONTACTS", label: "通讯录", runtime: true, controllable: false, granted: true, grant_state: "default" }] },
  { package_name: "com.example.familyclock", label: "家庭时钟", version_name: "2.4.1", version_code: 20401, target_sdk: 36, uid: 10201, system_app: false, enabled: true, suspended: false, hidden: false, network_blocked: false, installer: "com.android.packageinstaller", signer_sha256: "—", permissions: ["android.permission.CAMERA", "android.permission.POST_NOTIFICATIONS"], permission_details: [{ name: "android.permission.CAMERA", label: "相机", runtime: true, controllable: true, granted: true, grant_state: "default" }, { name: "android.permission.POST_NOTIFICATIONS", label: "通知", runtime: true, controllable: true, granted: false, grant_state: "default" }] },
  { package_name: "com.android.settings", label: "设置", version_name: "16", version_code: 36, target_sdk: 36, uid: 1000, system_app: true, enabled: true, suspended: false, hidden: false, network_blocked: false, installer: null, signer_sha256: "—", permissions: [], permission_details: [] },
];

let mockAudit: AuditEvent[] = [{
  id: "a-1",
  at: new Date().toISOString(),
  event: "system.ready",
  target: mockDevice.id,
  message: "开发环境初始设备已加载",
}];

const useMock = import.meta.env.VITE_MOCK === "true";

type AuthStatus = {
  ok: boolean;
  initialized: boolean;
  setup_required: boolean;
};

type PolicyUpdateResponse = {
  ok: boolean;
  policy_version: number;
  status: string;
  changed: string[];
};

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem("threepon.token");
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers ?? {}),
    },
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error ?? "请求失败");
  return payload as T;
}

export async function login(input: { username: string; password: string; otp: string }) {
  if (useMock) {
    if (input.username !== "admin" || input.password !== "change-this-password" || input.otp !== "000000") throw new Error("演示账号：admin / change-this-password / 000000");
    return { ok: true, token: "mock-session", user: "admin", demo_mode: true };
  }
  return request<{ ok: boolean; token: string; user: string; demo_mode: boolean }>("/api/v1/auth/login", { method: "POST", body: JSON.stringify(input) });
}

export async function getAuthStatus(): Promise<AuthStatus> {
  if (useMock) return { ok: true, initialized: true, setup_required: false };
  return request<AuthStatus>("/api/v1/auth/status");
}

export async function setupAdmin(input: { username: string; password: string; totp_secret: string; otp: string }) {
  if (useMock) return { ok: true, token: "mock-session", user: input.username, demo_mode: true };
  return request<{ ok: boolean; token: string; user: string; demo_mode: boolean }>("/api/v1/auth/setup", { method: "POST", body: JSON.stringify(input) });
}

export async function getDashboard(): Promise<Dashboard> {
  if (useMock) return { ok: true, devices: [mockDevice], pending_install_requests: mockRequests.filter((item) => item.status === "pending").length, online_devices: 1, pending_commands: 0 };
  return request<Dashboard>("/api/v1/dashboard");
}

export async function createPairingSession(input: { base_url: string; device_name?: string }): Promise<PairingSession> {
  if (useMock) {
    const sessionId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const payload = {
      kind: "3pon_pairing",
      version: 1,
      session_id: sessionId,
      pairing_token: `mock-${sessionId}`,
      base_url: input.base_url,
      server_public_key: "mock-server-public-key",
      update_manifest_url: `${input.base_url}/api/v1/device/update-manifest`,
      expires_at: expiresAt,
    };
    mockAudit.unshift({ id: crypto.randomUUID(), at: new Date().toISOString(), event: "device.pairing.created", target: sessionId, message: "管理员创建一次性扫码配对会话" });
    return { ok: true, session_id: sessionId, base_url: input.base_url, server_public_key: payload.server_public_key, update_manifest_url: payload.update_manifest_url, expires_at: expiresAt, qr_payload: JSON.stringify(payload) };
  }
  return request<PairingSession>("/api/v1/pairing/sessions", { method: "POST", body: JSON.stringify(input) });
}

export async function getBasicPolicy(deviceId: string): Promise<{ policy: BasicPolicy }> {
  if (useMock) return { policy: mockBasic };
  return request(`/api/v1/devices/${deviceId}/basic-policy`);
}

export async function getCallRuntimeStatus(deviceId: string): Promise<CallRuntimeStatus> {
  if (useMock) {
    return {
      ok: true,
      device_id: deviceId,
      device_owner_active: true,
      call_screening_role_available: true,
      call_screening_role_held: true,
      contacts_permission_granted: true,
      call_screening_enabled: mockBasic.call_screening_enabled,
      contacts_only_calls: mockBasic.contacts_only_calls,
      last_screened_call_at: null,
      screened_call_count: 0,
      blocked_call_count: 0,
      call_screening_status_updated_at: new Date().toISOString(),
    };
  }
  return request(`/api/v1/devices/${deviceId}/runtime-status`);
}

export async function updateBasicPolicy(deviceId: string, policy: BasicPolicy) {
  if (useMock) {
    if (policy.contacts_only_calls) policy.call_screening_enabled = true;
    mockBasic = policy;
    const networkSetting = mockSettings.find((item) => item.key === "network_default_mode");
    if (networkSetting) {
      networkSetting.value = policy.default_network_mode;
      networkSetting.status = "pending";
    }
    const installSetting = mockSettings.find((item) => item.key === "block_user_install");
    if (installSetting) {
      installSetting.value = policy.installation_approval_required;
      installSetting.status = "pending";
    }
    const protectionSetting = mockSettings.find((item) => item.key === "defender_uninstall_blocked");
    if (protectionSetting) {
      protectionSetting.value = policy.defender_self_protection;
      protectionSetting.status = "pending";
    }
    const callSetting = mockSettings.find((item) => item.key === "call_screening_enabled");
    if (callSetting) {
      callSetting.value = policy.call_screening_enabled;
      callSetting.status = "pending";
    }
    const contactsOnlySetting = mockSettings.find((item) => item.key === "contacts_only_calls");
    if (contactsOnlySetting) {
      contactsOnlySetting.value = policy.contacts_only_calls;
      contactsOnlySetting.status = "pending";
    }
    mockAudit.unshift({ id: crypto.randomUUID(), at: new Date().toISOString(), event: "policy.basic.update", target: deviceId, message: "基础控制策略已更新" });
    return { ok: true, policy_version: mockDevice.policy_version + 1, status: "pending_device_ack", changed: Object.keys(policy) };
  }
  return request<PolicyUpdateResponse>(`/api/v1/devices/${deviceId}/basic-policy`, { method: "PUT", body: JSON.stringify(policy) });
}

export async function getOwnerPolicy(deviceId: string): Promise<{ settings: OwnerSetting[]; version: number }> {
  if (useMock) return { settings: mockSettings, version: mockDevice.policy_version };
  return request(`/api/v1/devices/${deviceId}/owner-policy`);
}

export async function updateOwnerPolicy(deviceId: string, settings: Array<{ key: string; value: SettingValue }>) {
  if (useMock) {
    for (const patch of settings) {
      const setting = mockSettings.find((item) => item.key === patch.key);
      if (setting) {
        setting.value = patch.value;
        setting.status = "pending";
        setting.updated_at = new Date().toISOString();
      }
    }
    mockAudit.unshift({ id: crypto.randomUUID(), at: new Date().toISOString(), event: "policy.owner.update", target: deviceId, message: "设备所有者策略已更新" });
    return { ok: true, policy_version: mockDevice.policy_version + 1, status: "pending_device_ack", changed: settings.map((item) => item.key) };
  }
  return request<PolicyUpdateResponse>(`/api/v1/devices/${deviceId}/owner-policy`, { method: "PUT", body: JSON.stringify({ settings, reason: "管理台更新" }) });
}

export async function getInstallRequests(): Promise<{ requests: InstallRequest[] }> {
  if (useMock) return { requests: mockRequests };
  return request("/api/v1/install-requests");
}

export async function decideInstallRequest(id: string, decision: "approve" | "reject") {
  if (useMock) {
    const requestItem = mockRequests.find((item) => item.id === id);
    if (requestItem) requestItem.status = decision === "approve" ? "approved_pending_device" : "rejected";
    mockAudit.unshift({ id: crypto.randomUUID(), at: new Date().toISOString(), event: `install.${decision}d`, target: id, message: decision === "approve" ? "管理员批准应用安装" : "管理员拒绝应用安装" });
    return { ok: true };
  }
  return request(`/api/v1/install-requests/${id}/${decision}`, { method: "POST" });
}

export async function getDeviceApps(deviceId: string): Promise<DeviceApps> {
  if (useMock) {
    return { ok: true, device_id: deviceId, revision: `mock-${mockApps.length}-${mockApps.map((item) => `${item.package_name}:${item.suspended}:${item.network_blocked}`).join("|")}`, updated_at: new Date().toISOString(), apps: mockApps, pending_actions: [], update_status: "idle", update_version_code: 0 };
  }
  return request<DeviceApps>(`/api/v1/devices/${deviceId}/apps`);
}

export async function deviceAppAction(deviceId: string, packageName: string, action: "suspend" | "resume" | "network_block" | "network_allow" | "uninstall") {
  if (useMock) {
    const app = mockApps.find((item) => item.package_name === packageName);
    if (app && action === "suspend") app.suspended = true;
    if (app && action === "resume") app.suspended = false;
    if (app && action === "network_block") app.network_blocked = true;
    if (app && action === "network_allow") app.network_blocked = false;
    if (app && action === "uninstall") mockApps = mockApps.filter((item) => item.package_name !== packageName);
    mockAudit.unshift({ id: crypto.randomUUID(), at: new Date().toISOString(), event: `app.action.${action}`, target: deviceId, message: `已请求对 ${packageName} 执行${action}` });
    return { ok: true, command: { id: crypto.randomUUID(), status: "queued", kind: action } };
  }
  return request(`/api/v1/devices/${deviceId}/apps/${encodeURIComponent(packageName)}/action`, { method: "POST", body: JSON.stringify({ action }) });
}

export async function setDeviceAppPermission(deviceId: string, packageName: string, permission: string, grantState: "default" | "granted" | "denied") {
  if (useMock) {
    const app = mockApps.find((item) => item.package_name === packageName);
    const item = app?.permission_details.find((entry) => entry.name === permission);
    if (item) {
      item.grant_state = grantState;
      item.granted = grantState === "granted" ? true : grantState === "denied" ? false : item.granted;
    }
    return { ok: true, command: { id: crypto.randomUUID(), status: "queued", kind: "set_app_permission" } };
  }
  return request(`/api/v1/devices/${deviceId}/apps/${encodeURIComponent(packageName)}/permission`, { method: "POST", body: JSON.stringify({ permission, grant_state: grantState }) });
}

export async function getRecoveryKeys(): Promise<{ keys: RecoveryKey[] }> {
  if (useMock) return { keys: ["3A7D-9X2K-11QP", "5F2N-8M4R-7ZKC", "8Q1V-6B7L-2HJD", "9P4T-3C8W-6NLA"].map((value, index) => ({ id: `key-${index}`, value, used: index === 1 })) };
  return request("/api/v1/auth/recovery-keys");
}

export async function getAudit(): Promise<{ events: AuditEvent[] }> {
  if (useMock) return { events: mockAudit };
  return request("/api/v1/audit");
}
