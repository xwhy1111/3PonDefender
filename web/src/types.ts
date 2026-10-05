export type Device = {
  id: string;
  name: string;
  model: string;
  manufacturer: string;
  android_api: number;
  hyperos_version: string;
  base_url?: string;
  status: "online" | "offline" | string;
  last_seen_at: string;
  consent_version?: string | null;
  consented_at?: string | null;
  policy_version: number;
  apps_revision?: string;
  apps_updated_at?: string | null;
  app_count?: number;
  update_status?: string;
  update_version_code?: number;
  update_message?: string | null;
  update_updated_at?: string | null;
};

export type SettingValue = boolean | number | string | string[];

export type OwnerSetting = {
  key: string;
  category: string;
  label: string;
  description: string;
  kind: "boolean" | "integer" | "text" | "string_list" | string;
  value: SettingValue;
  supported: boolean;
  high_risk: boolean;
  status: "applied" | "pending" | string;
  updated_at: string;
};

export type BasicPolicy = {
  installation_approval_required: boolean;
  default_network_mode: string;
  defender_self_protection: boolean;
  background_protection_enabled: boolean;
  call_screening_enabled: boolean;
  call_allowlist: string[];
  contacts_only_calls: boolean;
  suspended_packages: string[];
};

export type CallRuntimeStatus = {
  ok: boolean;
  device_id: string;
  device_owner_active: boolean | null;
  call_screening_role_available: boolean | null;
  call_screening_role_held: boolean | null;
  contacts_permission_granted: boolean | null;
  call_screening_enabled: boolean | null;
  contacts_only_calls: boolean | null;
  last_screened_call_at: string | null;
  screened_call_count: number | null;
  blocked_call_count: number | null;
  call_screening_status_updated_at: string | null;
};

export type InstallRequest = {
  id: string;
  device_id: string;
  package_name: string;
  display_name: string;
  version: string;
  sha256: string;
  permissions: string[];
  status: string;
  requested_at: string;
};

export type ManagedApp = {
  package_name: string;
  label: string;
  version_name: string;
  version_code: number;
  target_sdk: number;
  uid: number;
  system_app: boolean;
  enabled: boolean;
  suspended: boolean;
  hidden: boolean;
  network_blocked: boolean;
  installer?: string | null;
  signer_sha256: string;
  permissions: string[];
  permission_details: ManagedPermission[];
};

export type ManagedPermission = {
  name: string;
  label: string;
  runtime: boolean;
  controllable: boolean;
  granted: boolean;
  grant_state: "default" | "granted" | "denied";
};

export type DeviceApps = {
  ok: boolean;
  device_id: string;
  revision: string;
  updated_at?: string | null;
  apps: ManagedApp[];
  pending_actions: Array<{ id: string; package_name: string; action: string; status: string; created_at: string }>;
  update_status: string;
  update_version_code: number;
  update_message?: string | null;
  update_updated_at?: string | null;
};

export type AuditEvent = {
  id: string;
  at: string;
  event: string;
  target: string;
  message: string;
};

export type RecoveryKey = {
  id: string;
  value: string;
  used: boolean;
  used_at?: string | null;
};

export type Dashboard = {
  ok: boolean;
  devices: Device[];
  pending_install_requests: number;
  online_devices: number;
  pending_commands: number;
};

export type PairingSession = {
  ok: boolean;
  session_id: string;
  base_url: string;
  server_public_key: string;
  update_manifest_url: string;
  expires_at: string;
  qr_payload: string;
};
