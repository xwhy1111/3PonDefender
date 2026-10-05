import { FormEvent, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { QRCodeSVG } from "qrcode.react";
import {
  Activity,
  AppWindow,
  Ban,
  Check,
  ChevronRight,
  Clock3,
  CloudOff,
  Copy,
  Database,
  FileCheck2,
  FileKey2,
  Fingerprint,
  Globe2,
  Gauge,
  KeyRound,
  LaptopMinimal,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  Network,
  Phone,
  Plus,
  PlugZap,
  QrCode,
  RotateCcw,
  Save,
  Search,
  ServerCog,
  Settings2,
  SlidersHorizontal,
  Shield,
  ShieldCheck,
  Smartphone,
  TerminalSquare,
  TriangleAlert,
  UserRoundCheck,
  Volume2,
  Wifi,
  X,
} from "lucide-react";
import * as api from "./api";
import type { AuditEvent, BasicPolicy, CallRuntimeStatus, Dashboard, Device, DeviceApps, InstallRequest, ManagedApp, ManagedPermission, OwnerSetting, PairingSession, RecoveryKey, SettingValue } from "./types";
import "./styles.css";

type View = "dashboard" | "basic" | "owner" | "system" | "apps" | "network" | "calls" | "security";

const navItems: Array<{ id: View; label: string; icon: typeof LayoutDashboard; group: string }> = [
  { id: "dashboard", label: "设备总览", icon: LayoutDashboard, group: "工作台" },
  { id: "basic", label: "基础控制", icon: ShieldCheck, group: "基础管控" },
  { id: "apps", label: "应用管理", icon: AppWindow, group: "基础管控" },
  { id: "network", label: "联网与流量", icon: Network, group: "基础管控" },
  { id: "calls", label: "电话白名单", icon: Phone, group: "基础管控" },
  { id: "owner", label: "设备所有者", icon: Settings2, group: "高级策略" },
  { id: "system", label: "系统设置", icon: SlidersHorizontal, group: "高级策略" },
  { id: "security", label: "安全与审计", icon: KeyRound, group: "系统" },
];

function App() {
  const [token, setToken] = useState(localStorage.getItem("threepon.token"));
  const [setupRequired, setSetupRequired] = useState<boolean | null>(null);
  const [view, setView] = useState<View>("dashboard");
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [pairingOpen, setPairingOpen] = useState(false);

  useEffect(() => {
    let active = true;
    api.getAuthStatus()
      .then((status) => { if (active) setSetupRequired(status.setup_required); })
      .catch(() => { if (active) setSetupRequired(false); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (!setupRequired || !token) return;
    localStorage.removeItem("threepon.token");
    setToken(null);
  }, [setupRequired, token]);

  useEffect(() => {
    if (!token) return;
    api.getDashboard().then(setDashboard).catch(() => {
      localStorage.removeItem("threepon.token");
      setDashboard(null);
      setToken(null);
    });
  }, [token]);

  if (!token) {
    if (setupRequired === null) return <AuthLoading />;
    if (setupRequired) return <SetupPage onInitialized={(nextToken) => { localStorage.setItem("threepon.token", nextToken); setSetupRequired(false); setToken(nextToken); }} />;
    return <LoginPage onLogin={(nextToken) => { localStorage.setItem("threepon.token", nextToken); setToken(nextToken); }} />;
  }

  const device = dashboard?.devices.find((item) => item.status === "online") ?? dashboard?.devices[0] ?? null;
  const logout = () => { localStorage.removeItem("threepon.token"); setToken(null); };
  return <AppShell device={device} view={view} setView={setView} logout={logout} onPairDevice={() => setPairingOpen(true)}>
    {view === "dashboard" && <DashboardView dashboard={dashboard} onNavigate={setView} />}
    {view === "basic" && device && <BasicView device={device} />}
    {view === "apps" && device && <AppsView device={device} />}
    {view === "network" && device && <NetworkView device={device} />}
    {view === "calls" && device && <CallsView device={device} />}
    {view === "owner" && device && <OwnerView device={device} />}
    {view === "system" && device && <SystemSettingsView device={device} />}
    {view === "security" && <SecurityView />}
    {pairingOpen && <PairingDialog onClose={() => setPairingOpen(false)} />}
  </AppShell>;
}

function SetupPage({ onInitialized }: { onInitialized: (token: string) => void }) {
  const [secret, setSecret] = useState(generateTotpSecret);
  const [form, setForm] = useState({ username: "", password: "", confirmPassword: "", otp: "" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const otpauthUri = useMemo(() => {
    const account = form.username.trim() || "管理员";
    return `otpauth://totp/${encodeURIComponent(`3Pon Defender:${account}`)}?secret=${secret}&issuer=${encodeURIComponent("3Pon Defender")}`;
  }, [form.username, secret]);

  const regenerateSecret = () => {
    setSecret(generateTotpSecret());
    setForm((current) => ({ ...current, otp: "" }));
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (form.password !== form.confirmPassword) {
      setError("两次输入的密码不一致");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const result = await api.setupAdmin({ username: form.username, password: form.password, totp_secret: secret, otp: form.otp });
      onInitialized(result.token);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "初始化失败");
    } finally {
      setBusy(false);
    }
  };

  return <main className="login-page">
    <section className="login-panel">
      <div className="login-card setup-card">
        <div className="login-card-head"><div className="login-identity"><img className="brand-mark login-brand-mark" src="/threepon-logo.jpg" alt="3Pon Defender Logo" /><div><strong>3Pon Defender</strong><span>首次初始化</span></div></div><ShieldCheck size={20} /></div>
        <div className="login-heading"><h1>创建管理员</h1><p>这是第一次进入管控台。先创建管理员账号并绑定 OTP，之后每次登录都需要验证。</p></div>
        <div className="setup-totp-box">
          <div className="setup-qr"><QRCodeSVG value={otpauthUri} size={156} level="M" includeMargin bgColor="#ffffff" fgColor="#15221f" /></div>
          <div className="setup-totp-copy"><span className="section-kicker">AUTHENTICATOR</span><strong>扫描二维码绑定 OTP</strong><p>使用手机认证器扫描后，输入认证器显示的 6 位验证码。</p><code>{secret}</code><div className="setup-totp-actions"><button type="button" className="icon-button" title="复制 TOTP 密钥" onClick={() => void navigator.clipboard?.writeText(secret)}><Copy size={15} /></button><button type="button" className="text-button" onClick={regenerateSecret}><RotateCcw size={14} />重新生成密钥</button></div></div>
        </div>
        <form onSubmit={submit} className="form-stack setup-form">
          <label>管理员用户名<input value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} autoComplete="username" minLength={3} maxLength={64} required /></label>
          <label>管理员密码<input type="password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} autoComplete="new-password" minLength={9} required /></label>
          <label>确认密码<input type="password" value={form.confirmPassword} onChange={(event) => setForm({ ...form, confirmPassword: event.target.value })} autoComplete="new-password" minLength={9} required /></label>
          <label>当前 OTP 验证码<input inputMode="numeric" pattern="[0-9]*" maxLength={6} value={form.otp} onChange={(event) => setForm({ ...form, otp: event.target.value.replace(/\D/g, "") })} autoComplete="one-time-code" required /></label>
          {error && <div className="error-strip"><Ban size={16} />{error}</div>}
          <button className="primary-button full" disabled={busy}>{busy ? "正在初始化…" : "完成初始化"}<ChevronRight size={17} /></button>
        </form>
        <div className="login-note"><Fingerprint size={16} /><span>初始化完成后会生成一次性恢复密钥，请登录后在“安全与审计”页面保存。</span></div>
      </div>
    </section>
  </main>;
}

function LoginPage({ onLogin }: { onLogin: (token: string) => void }) {
  const [form, setForm] = useState({ username: "", password: "", otp: "" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setBusy(true); setError("");
    try { const result = await api.login(form); onLogin(result.token); }
    catch (caught) { setError(caught instanceof Error ? caught.message : "登录失败"); }
    finally { setBusy(false); }
  };
  return <main className="login-page">
    <section className="login-panel">
      <div className="login-card">
        <div className="login-card-head"><div className="login-identity"><img className="brand-mark login-brand-mark" src="/threepon-logo.jpg" alt="3Pon Defender Logo" /><div><strong>3Pon Defender</strong><span>管理员登录</span></div></div><LockKeyhole size={20} /></div>
        <div className="login-heading"><h1>进入管控台</h1><p>请使用管理员凭据登录。</p></div>
        <form onSubmit={submit} className="form-stack">
          <label>管理员用户名<input value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} autoComplete="username" /></label>
          <label>密码<input type="password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} autoComplete="current-password" /></label>
          <label>OTP 验证码<input inputMode="numeric" maxLength={6} value={form.otp} onChange={(event) => setForm({ ...form, otp: event.target.value.replace(/\D/g, "") })} /></label>
          {error && <div className="error-strip"><Ban size={16} />{error}</div>}
          <button className="primary-button full" disabled={busy}>{busy ? "验证中…" : "安全登录"}<ChevronRight size={17} /></button>
        </form>
        <div className="login-note"><Fingerprint size={16} /><span>登录需要管理员用户名、密码和认证器当前 OTP。恢复密钥只在登录后的安全页显示。</span></div>
      </div>
    </section>
  </main>;
}

function AuthLoading() {
  return <main className="login-page"><div className="login-card auth-loading"><span className="spinner" /><span>正在读取安全状态…</span></div></main>;
}

function AppShell({ device, view, setView, logout, onPairDevice, children }: { device: Device | null; view: View; setView: (view: View) => void; logout: () => void; onPairDevice: () => void; children: React.ReactNode }) {
  const grouped = navItems.reduce<Record<string, typeof navItems>>((result, item) => { (result[item.group] ??= []).push(item); return result; }, {});
  return <div className="app-shell">
    <aside className="sidebar">
      <div className="sidebar-brand"><img className="brand-mark small" src="/threepon-logo.jpg" alt="3Pon Defender Logo" /><div><strong>3Pon</strong><span>Defender</span></div></div>
      <div className="workspace-chip"><span className="pulse-dot" /><div><strong>本地管控空间</strong><small>单管理员 · {device?.model ?? "未连接"}</small></div></div>
      <nav className="nav-list">
        {Object.entries(grouped).map(([group, items]) => <div className="nav-group" key={group}><span className="nav-group-title">{group}</span>{items.map((item) => { const Icon = item.icon; return <button key={item.id} className={view === item.id ? "nav-item active" : "nav-item"} onClick={() => setView(item.id)}><Icon size={17} /><span>{item.label}</span>{view === item.id && <ChevronRight size={14} />}</button>; })}</div>)}
      </nav>
      <div className="sidebar-bottom"><div className="server-status"><span className="pulse-dot" /><div><strong>控制服务在线</strong><small>HTTP / 10 秒轮询</small></div></div><button className="logout-button" onClick={logout}><LogOut size={16} />退出管理员会话</button></div>
    </aside>
    <main className="main-content">
      <header className="topbar"><div className="breadcrumb"><span>3Pon Defender</span><ChevronRight size={14} /><strong>{navItems.find((item) => item.id === view)?.label}</strong></div><div className="topbar-actions"><button className="secondary-button pair-button" onClick={onPairDevice}><QrCode size={16} />绑定新设备</button><div className="device-chip"><span className="online-dot" /><Smartphone size={15} /><span>{device?.name ?? "未连接设备"}</span></div><span className="admin-chip"><UserRoundCheck size={15} />管理员</span></div></header>
      <div className="page-body">{children}</div>
    </main>
  </div>;
}

function PairingDialog({ onClose }: { onClose: () => void }) {
  const [session, setSession] = useState<PairingSession | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const baseUrl = window.location.origin;
  const loopback = ["localhost", "127.0.0.1", "[::1]", "::1"].includes(window.location.hostname);

  const generate = async () => {
    setBusy(true);
    setError("");
    try {
      setSession(await api.createPairingSession({ base_url: baseUrl, device_name: "长辈手机" }));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "二维码生成失败");
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => { void generate(); }, []);

  return <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
    <section className="pairing-dialog" role="dialog" aria-modal="true" aria-labelledby="pairing-title">
      <header className="pairing-dialog-head"><div><span className="eyebrow">DEVICE PAIRING</span><h2 id="pairing-title">绑定新设备</h2><p>二维码只允许使用一次，10 分钟后失效。</p></div><button className="icon-button" title="关闭" onClick={onClose}><X size={18} /></button></header>
      <div className="pairing-content">
        <div className="qr-frame">{session ? <QRCodeSVG value={session.qr_payload} size={236} level="M" includeMargin bgColor="#ffffff" fgColor="#15221f" /> : <span className="spinner" />}</div>
        <div className="pairing-details">
          <div className="pairing-address"><Globe2 size={18} /><div><small>被管控端连接地址</small><code>{baseUrl}</code></div></div>
          {loopback && <div className="error-strip"><TriangleAlert size={16} /><span>当前是回环地址，手机无法访问。请用局域网 IP 或可访问域名打开本管理台后重新生成。</span></div>}
          {error && <div className="error-strip"><Ban size={16} />{error}</div>}
          <div className="pairing-checklist"><strong>配对确认</strong><span>手机扫码后会展示功能说明；只有用户明确同意且设备已注册为 Device Owner，服务器才会发放设备凭据。</span></div>
          {session && <div className="pairing-expiry"><span>会话有效期</span><strong>{formatTime(session.expires_at)}</strong></div>}
          <button className="secondary-button" onClick={() => void generate()} disabled={busy}><RotateCcw size={16} />{busy ? "生成中…" : "重新生成二维码"}</button>
        </div>
      </div>
    </section>
  </div>;
}

function PageHeader({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: React.ReactNode }) {
  return <div className="page-header"><div><span className="eyebrow">{eyebrow}</span><h1>{title}</h1><p>{description}</p></div>{action}</div>;
}

function Metric({ icon: Icon, label, value, detail, tone = "neutral" }: { icon: typeof Activity; label: string; value: string; detail: string; tone?: string }) {
  return <div className="metric"><span className={`metric-icon ${tone}`}><Icon size={17} /></span><div><small>{label}</small><strong>{value}</strong><em>{detail}</em></div></div>;
}

function StatusPill({ status }: { status: string }) {
  const map: Record<string, [string, string]> = { online: ["在线", "good"], offline: ["离线", "danger"], pending: ["待审批", "warn"], approved_pending_device: ["等待设备", "accent"], rejected: ["已拒绝", "danger"], applied: ["已生效", "good"], pending_device_ack: ["等待设备确认", "warn"], idle: ["暂无更新", "neutral"], checking: ["检查更新", "accent"], downloading: ["下载中", "accent"], verifying: ["校验中", "accent"], installing: ["安装中", "warn"], failed: ["更新失败", "danger"] };
  const [label, tone] = map[status] ?? [status, "neutral"];
  return <span className={`status-pill ${tone}`}><span />{label}</span>;
}

function DashboardView({ dashboard, onNavigate }: { dashboard: Dashboard | null; onNavigate: (view: View) => void }) {
  const device = dashboard?.devices[0];
  const [requests, setRequests] = useState<InstallRequest[]>([]);
  useEffect(() => { api.getInstallRequests().then((result) => setRequests(result.requests)); }, []);
  return <>
    <PageHeader eyebrow="CONTROL OVERVIEW" title="设备总览" description="查看设备连接、策略生效和需要管理员处理的事项。" action={<button className="secondary-button" onClick={() => onNavigate("owner")}><Settings2 size={16} />打开 Owner 面板</button>} />
    <section className="metric-grid"><Metric icon={Smartphone} label="受控设备" value={`${dashboard?.devices.length ?? 0}`} detail="台设备已绑定" tone="accent" /><Metric icon={Wifi} label="在线状态" value={`${dashboard?.online_devices ?? 0}`} detail="设备实时在线" tone="good" /><Metric icon={AppWindow} label="安装审批" value={`${dashboard?.pending_install_requests ?? requests.filter((item) => item.status === "pending").length}`} detail="项等待处理" tone="warn" /><Metric icon={Activity} label="策略队列" value={`${dashboard?.pending_commands ?? 0}`} detail="条命令等待确认" /></section>
    <section className="content-grid two-one">
      <div className="panel"><div className="panel-title"><div><span className="section-kicker">DEVICE CONNECTION</span><h2>受控设备</h2></div><button className="icon-button" title="刷新设备" onClick={() => window.location.reload()}><RotateCcw size={16} /></button></div>{device ? <div className="device-row featured"><div className="device-avatar"><Smartphone size={23} /></div><div className="device-info"><strong>{device.name}</strong><span>{device.model} · Android {device.android_api} · {device.hyperos_version}</span><small>最后在线 {formatTime(device.last_seen_at)} · 策略版本 v{device.policy_version}</small></div><StatusPill status={device.status} /><button className="row-arrow" onClick={() => onNavigate("basic")}><ChevronRight size={18} /></button></div> : <EmptyState icon={CloudOff} title="暂无设备" text="完成设备端配对后，设备会显示在这里。" />}</div>
      <div className="panel alert-panel"><div className="panel-title"><div><span className="section-kicker">NEXT ACTION</span><h2>待处理事项</h2></div><Gauge size={18} /></div><button className="action-row" onClick={() => onNavigate("apps")}><span className="action-icon warn"><AppWindow size={16} /></span><span><strong>{requests.filter((item) => item.status === "pending").length} 个应用安装申请</strong><small>查看包名、签名和权限</small></span><ChevronRight size={16} /></button><button className="action-row" onClick={() => onNavigate("security")}><span className="action-icon accent"><KeyRound size={16} /></span><span><strong>恢复密钥可用</strong><small>管理员安全页面持续显示</small></span><ChevronRight size={16} /></button></div>
    </section>
    <section className="panel"><div className="panel-title"><div><span className="section-kicker">RECENT ACTIVITY</span><h2>最近审计活动</h2></div><button className="text-button" onClick={() => onNavigate("security")}>查看全部 <ChevronRight size={14} /></button></div><AuditTable compact /></section>
  </>;
}

function BasicView({ device }: { device: Device }) {
  const [policy, setPolicy] = useState<BasicPolicy | null>(null);
  const [saved, setSaved] = useState("");
  useEffect(() => { api.getBasicPolicy(device.id).then((result) => setPolicy(result.policy)); }, [device.id]);
  if (!policy) return <Loading />;
  const update = (patch: Partial<BasicPolicy>) => setPolicy({ ...policy, ...patch });
  const save = async () => { await api.updateBasicPolicy(device.id, policy); setSaved("已提交设备，等待实际生效确认"); setTimeout(() => setSaved(""), 3500); };
  return <>
    <PageHeader eyebrow="BASIC CONTROLS" title="基础控制" description="针对日常照护场景的精选控制项。高级能力请进入设备所有者面板。" action={<button className="primary-button" onClick={save}><Save size={16} />保存基础策略</button>} />
    {saved && <div className="success-strip"><Check size={16} />{saved}</div>}
    <section className="control-list">
      <ControlRow icon={Shield} title="应用安装审批" description="关闭后同时解除“禁止安装应用”和“禁止未知来源”两条 Android 限制，用户即可正常安装。" checked={policy.installation_approval_required} onChange={(checked) => update({ installation_approval_required: checked })} risk />
      <ControlRow icon={Network} title="默认联网策略" description="未明确允许的应用默认阻断联网，并采集连接元数据。" checked={policy.default_network_mode === "deny_unlisted"} onChange={(checked) => update({ default_network_mode: checked ? "deny_unlisted" : "allow_all" })} risk />
      <ControlRow icon={LockKeyhole} title="3Pon Defender 防卸载" description="阻止被管控端用户卸载管控客户端。解除需要管理员高风险授权。" checked={policy.defender_self_protection} onChange={(checked) => update({ defender_self_protection: checked })} risk />
      <ControlRow icon={ShieldCheck} title="Defender 后台保护" description="保持前台轮询服务、开机恢复和任务移除后的自恢复；小米设备仍需允许自启动和电池不受限制。" checked={policy.background_protection_enabled} onChange={(checked) => update({ background_protection_enabled: checked })} />
      <ControlRow icon={Phone} title="电话白名单筛选" description="限制非白名单来电，紧急号码作为系统安全例外保留。关闭时会同时关闭通讯录筛选。" checked={policy.call_screening_enabled} onChange={(checked) => update(checked ? { call_screening_enabled: true } : { call_screening_enabled: false, contacts_only_calls: false })} />
      <ControlRow icon={Phone} title="仅允许通讯录来电" description="开启后会自动启用总来电筛选；仅紧急号码、白名单和设备通讯录中保存的号码可以呼入。" checked={policy.contacts_only_calls} onChange={(checked) => update(checked ? { contacts_only_calls: true, call_screening_enabled: true } : { contacts_only_calls: false })} risk />
    </section>
    <section className="panel"><div className="panel-title"><div><span className="section-kicker">SUSPENDED PACKAGES</span><h2>已禁用应用</h2></div><span className="muted-count">{policy.suspended_packages.length} 个</span></div><div className="package-input"><input value={policy.suspended_packages.join("\n")} onChange={(event) => update({ suspended_packages: event.target.value.split(/\n|,/).map((item) => item.trim()).filter(Boolean) })} placeholder="每行输入一个包名，例如 com.example.game" /><small>保存后由设备所有者调用应用暂停策略。</small></div></section>
  </>;
}

function ControlRow({ icon: Icon, title, description, checked, onChange, risk }: { icon: typeof Shield; title: string; description: string; checked: boolean; onChange: (value: boolean) => void; risk?: boolean }) {
  return <div className="control-row"><span className="control-icon"><Icon size={18} /></span><div className="control-copy"><strong>{title}{risk && <span className="risk-tag">策略</span>}</strong><p>{description}</p></div><button className={checked ? "toggle active" : "toggle"} aria-pressed={checked} onClick={() => onChange(!checked)}><span /></button></div>;
}

function AppsView({ device }: { device: Device }) {
  const [requests, setRequests] = useState<InstallRequest[]>([]);
  const [catalog, setCatalog] = useState<DeviceApps | null>(null);
  const [filter, setFilter] = useState("");
  const [showSystemApps, setShowSystemApps] = useState(false);
  const [permissionApp, setPermissionApp] = useState<ManagedApp | null>(null);
  const [permissionBusy, setPermissionBusy] = useState("");
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const loadApps = async () => {
    try { setCatalog(await api.getDeviceApps(device.id)); }
    catch (caught) { setMessage(caught instanceof Error ? caught.message : "读取应用清单失败"); }
  };
  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const [apps, installRequests] = await Promise.all([api.getDeviceApps(device.id), api.getInstallRequests()]);
        if (active) { setCatalog(apps); setRequests(installRequests.requests); }
      } catch (caught) { if (active) setMessage(caught instanceof Error ? caught.message : "读取应用数据失败"); }
    };
    void load();
    const timer = window.setInterval(() => { void load(); }, 10000);
    return () => { active = false; window.clearInterval(timer); };
  }, [device.id]);
  const decide = async (id: string, decision: "approve" | "reject") => { await api.decideInstallRequest(id, decision); setRequests((items) => items.map((item) => item.id === id ? { ...item, status: decision === "approve" ? "approved_pending_device" : "rejected" } : item)); };
  const action = async (app: ManagedApp, next: "suspend" | "resume" | "network_block" | "network_allow" | "uninstall") => {
    if (next === "uninstall" && !window.confirm(`确定要从 ${device.name} 卸载“${app.label}”吗？该操作会排队，设备在线后执行。`)) return;
    if (next === "network_block" && !window.confirm(`确定禁止“${app.label}”联网吗？Android 端会通过本地 VPN 丢弃该应用的数据包。`)) return;
    setBusy(`${app.package_name}:${next}`); setMessage("");
    try {
      await api.deviceAppAction(device.id, app.package_name, next);
      setMessage(`已提交${next === "uninstall" ? "卸载" : next === "network_block" ? "禁止联网" : next === "network_allow" ? "允许联网" : next === "suspend" ? "停用" : "恢复"}命令，等待设备轮询执行`);
      await loadApps();
    } catch (caught) { setMessage(caught instanceof Error ? caught.message : "应用操作提交失败"); }
    finally { setBusy(""); }
  };
  const setPermission = async (app: ManagedApp, permission: ManagedPermission, grantState: "default" | "granted" | "denied") => {
    if (grantState === "denied" && !window.confirm(`确定拒绝“${app.label}”的“${permission.label}”权限吗？应用的相关功能可能无法使用。`)) return;
    setPermissionBusy(permission.name);
    setMessage("");
    try {
      await api.setDeviceAppPermission(device.id, app.package_name, permission.name, grantState);
      setMessage(`已提交“${permission.label}”权限策略，等待设备轮询执行`);
      setPermissionApp({ ...app, permission_details: app.permission_details.map((item) => item.name === permission.name ? { ...item, grant_state: grantState } : item) });
    } catch (caught) { setMessage(caught instanceof Error ? caught.message : "权限策略提交失败"); }
    finally { setPermissionBusy(""); }
  };
  const visibleApps = (catalog?.apps ?? []).filter((item) => (showSystemApps || !item.system_app) && `${item.label} ${item.package_name}`.toLowerCase().includes(filter.toLowerCase()));
  const visibleRequests = requests.filter((item) => `${item.display_name} ${item.package_name}`.toLowerCase().includes(filter.toLowerCase()));
  const hiddenSystemCount = (catalog?.apps ?? []).filter((item) => item.system_app).length;
  return <>
    <PageHeader eyebrow="APPLICATION GOVERNANCE" title="应用管理" description="管理被管控端应用的运行状态、联网能力和 Android 运行时权限。系统应用默认隐藏，所有变更在设备下一次轮询时执行。" action={<button className="secondary-button" onClick={() => void loadApps()} disabled={busy !== ""}><RotateCcw size={16} />刷新清单</button>} />
    <section className="metric-grid app-metrics"><Metric icon={AppWindow} label="已上报应用" value={`${catalog?.apps.length ?? 0}`} detail={catalog?.updated_at ? `清单更新于 ${formatTime(catalog.updated_at)}` : "等待设备上报"} tone="accent" /><Metric icon={ShieldCheck} label="受保护应用" value={`${(catalog?.apps ?? []).filter((item) => item.system_app || item.package_name === "com.threepon.defender").length}`} detail="系统应用或 Defender" tone="good" /><Metric icon={Ban} label="已禁用 / 断网" value={`${(catalog?.apps ?? []).filter((item) => item.suspended || item.network_blocked).length}`} detail="设备实际状态" tone="warn" /><Metric icon={RotateCcw} label="自动更新" value={catalog?.update_status === "idle" ? "正常" : catalog?.update_status ?? "未知"} detail={catalog?.update_version_code ? `目标 v${catalog.update_version_code}` : "10 秒轮询清单"} /></section>
    {message && <div className="success-strip"><Check size={16} />{message}</div>}
    <section className="panel"><div className="panel-title apps-panel-title"><div><span className="section-kicker">DEVICE APPLICATION INVENTORY</span><h2>设备应用清单</h2><small className="panel-subtitle">{catalog?.revision ? `revision ${catalog.revision.slice(0, 12)} · ` : ""}{showSystemApps ? "显示全部应用" : `已隐藏 ${hiddenSystemCount} 个系统应用`}</small></div><div className="app-list-tools"><label className="system-app-toggle"><span>显示系统应用</span><button className={showSystemApps ? "toggle active" : "toggle"} aria-pressed={showSystemApps} onClick={() => setShowSystemApps(!showSystemApps)}><span /></button></label><label className="search-field"><Search size={15} /><input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="搜索应用或包名" /></label></div></div><div className="table-wrap"><table className="apps-table"><thead><tr><th>应用</th><th>版本</th><th>状态</th><th>运行时权限</th><th>安装来源</th><th>操作</th></tr></thead><tbody>{visibleApps.map((item) => { const protectedApp = item.package_name === "com.threepon.defender"; const currentBusy = busy.startsWith(`${item.package_name}:`); const pending = catalog?.pending_actions.find((entry) => entry.package_name === item.package_name); const runtimePermissions = item.permission_details?.filter((permission) => permission.runtime) ?? []; return <tr key={item.package_name}><td><div className="app-cell"><span className={protectedApp ? "app-icon protected" : "app-icon"}>{protectedApp ? <ShieldCheck size={17} /> : <AppWindow size={17} />}</span><span><strong>{item.label}{item.system_app && <span className="system-tag">系统</span>}</strong><small>{item.package_name} · UID {item.uid}</small></span></div></td><td><code>{item.version_name || "—"} ({item.version_code})</code></td><td><div className="app-state-list"><span className={item.enabled ? "state-on" : "state-off"}>{item.enabled ? "启用" : "停用"}</span>{item.suspended && <span className="state-warn">已暂停</span>}{item.hidden && <span className="state-warn">已隐藏</span>}{item.network_blocked && <span className="state-danger">已断网</span>}{pending && <span className="state-pending">命令排队中</span>}</div></td><td><button className="permission-count" onClick={() => setPermissionApp(item)}><KeyRound size={14} />{runtimePermissions.length} 项</button></td><td><code>{item.installer ?? "系统预装"}</code></td><td>{protectedApp ? <span className="protected-label"><ShieldCheck size={14} />受保护</span> : <div className="table-actions app-actions"><button className="mini-action" disabled={currentBusy || Boolean(pending)} onClick={() => void action(item, item.suspended ? "resume" : "suspend")}>{item.suspended ? "恢复" : "停用"}</button><button className={item.network_blocked ? "mini-action allowed" : "mini-action"} disabled={currentBusy || Boolean(pending)} onClick={() => void action(item, item.network_blocked ? "network_allow" : "network_block")}>{item.network_blocked ? "允许联网" : "禁止联网"}</button><button className="mini-action danger-action" disabled={currentBusy || Boolean(pending)} onClick={() => void action(item, "uninstall")}>卸载</button></div>}</td></tr>; })}</tbody></table>{catalog && catalog.apps.length > 0 && visibleApps.length === 0 && <EmptyState icon={Search} title="没有匹配的应用" text={showSystemApps ? "换一个应用名称或包名试试。" : "当前筛选下没有第三方应用，可打开“显示系统应用”。"} />}{!catalog && <Loading />}</div></section>
    <section className="panel"><div className="panel-title"><div><span className="section-kicker">INSTALL REQUESTS</span><h2>安装审批</h2></div><span className="muted-count">{visibleRequests.filter((item) => item.status === "pending").length} 项待处理</span></div><div className="table-wrap"><table><thead><tr><th>应用</th><th>版本</th><th>SHA-256</th><th>权限</th><th>状态</th><th>操作</th></tr></thead><tbody>{visibleRequests.map((item) => <tr key={item.id}><td><div className="app-cell"><span className="app-icon"><AppWindow size={17} /></span><span><strong>{item.display_name}</strong><small>{item.package_name}</small></span></div></td><td><code>{item.version}</code></td><td><code>{item.sha256}</code></td><td><div className="permission-list">{item.permissions.map((permission) => <span key={permission}>{permission}</span>)}</div></td><td><StatusPill status={item.status} /></td><td>{item.status === "pending" ? <div className="table-actions"><button className="approve-button" onClick={() => void decide(item.id, "approve")}><Check size={14} />批准</button><button className="reject-button" onClick={() => void decide(item.id, "reject")}><X size={14} />拒绝</button></div> : <span className="muted-text">已处理</span>}</td></tr>)}</tbody></table></div></section>
    <section className="notice-band"><ShieldCheck size={18} /><div><strong>Defender 软件锁后台运行</strong><p>3Pon Defender 自身不会出现在可操作按钮中，也不会接受卸载、隐藏、停用或断网命令。应用状态每 10 秒刷新，自动更新由同一轮询服务触发。</p></div></section>
    {permissionApp && <PermissionDialog app={permissionApp} busy={permissionBusy} onChange={(permission, state) => void setPermission(permissionApp, permission, state)} onClose={() => setPermissionApp(null)} />}
  </>;
}

function PermissionDialog({ app, busy, onChange, onClose }: { app: ManagedApp; busy: string; onChange: (permission: ManagedPermission, state: "default" | "granted" | "denied") => void; onClose: () => void }) {
  const permissions = app.permission_details ?? [];
  return <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><section className="permission-dialog" role="dialog" aria-modal="true" aria-label={`${app.label} 权限`}><header className="permission-dialog-head"><div className="app-cell"><span className="app-icon"><AppWindow size={18} /></span><span><strong>{app.label}</strong><small>{app.package_name} · target SDK {app.target_sdk}</small></span></div><button className="icon-button" title="关闭" onClick={onClose}><X size={17} /></button></header><div className="permission-dialog-body">{permissions.map((permission) => <div className="permission-row" key={permission.name}><div><strong>{permission.label}</strong><small>{permission.name}</small></div>{permission.controllable ? <select value={permission.grant_state} disabled={busy === permission.name} onChange={(event) => onChange(permission, event.target.value as "default" | "granted" | "denied")}><option value="default">跟随系统</option><option value="granted">允许</option><option value="denied">拒绝</option></select> : <span className={permission.granted ? "permission-state granted" : "permission-state"}>{permission.runtime ? (permission.granted ? "已允许" : "未允许") : "不可管控"}</span>}</div>)}{permissions.length === 0 && <EmptyState icon={KeyRound} title="没有权限声明" text="设备没有上报这个应用的权限。" />}</div><footer className="permission-dialog-foot"><span>只有 Android 危险级运行时权限可由 Device Owner 固定。</span><button className="secondary-button" onClick={onClose}>完成</button></footer></section></div>;
}

function NetworkView({ device }: { device: Device }) {
  return <><PageHeader eyebrow="NETWORK GOVERNANCE" title="联网与流量" description="应用级联网规则和流量元数据。当前方案不解密 HTTPS，也不记录通信正文。" action={<button className="secondary-button"><PlugZap size={16} />刷新连接状态</button>} /><section className="metric-grid"><Metric icon={Wifi} label="VPN 状态" value="Lockdown" detail="Always-on VPN 已启用" tone="good" /><Metric icon={Network} label="默认规则" value="Deny unlisted" detail="未允许应用默认阻断" tone="accent" /><Metric icon={Database} label="今日元数据" value="1,284" detail="条连接记录" /><Metric icon={Clock3} label="最后同步" value="刚刚" detail={`${device.name} 在线`} /></section><section className="content-grid two-one"><div className="panel"><div className="panel-title"><div><span className="section-kicker">APP NETWORK POLICY</span><h2>应用联网规则</h2></div><StatusPill status="applied" /></div><div className="network-rule"><span className="app-icon"><ShieldCheck size={17} /></span><div><strong>3Pon Defender</strong><small>com.threepon.defender</small></div><span className="rule-allow">始终允许</span></div><div className="network-rule"><span className="app-icon"><AppWindow size={17} /></span><div><strong>家庭时钟</strong><small>com.example.familyclock</small></div><span className="rule-allow">允许</span></div><div className="network-rule muted"><span className="app-icon"><Ban size={17} /></span><div><strong>未批准应用</strong><small>所有未列入策略的 UID</small></div><span className="rule-block">阻断</span></div></div><div className="panel"><div className="panel-title"><div><span className="section-kicker">TRAFFIC META</span><h2>最近连接</h2></div><button className="text-button">导出 <ChevronRight size={14} /></button></div><div className="traffic-list"><TrafficRow app="家庭时钟" host="api.family.example" value="允许 · 42 KB" /><TrafficRow app="未批准应用" host="cdn.unknown.example" value="阻断 · 0 B" /><TrafficRow app="系统更新" host="update.miui.com" value="允许 · 1.2 MB" /></div></div></section></>;
}

function TrafficRow({ app, host, value }: { app: string; host: string; value: string }) { return <div className="traffic-row"><span className="pulse-dot" /><div><strong>{app}</strong><small>{host}</small></div><code>{value}</code></div>; }

function CallsView({ device }: { device: Device }) {
  const [numbers, setNumbers] = useState(["110", "120", "119"]);
  const [contactsOnlyCalls, setContactsOnlyCalls] = useState(false);
  const [callScreeningEnabled, setCallScreeningEnabled] = useState(true);
  const [runtimeStatus, setRuntimeStatus] = useState<CallRuntimeStatus | null>(null);
  const [newNumber, setNewNumber] = useState("");
  const [adding, setAdding] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    let active = true;
    const refresh = async () => {
      const [policyResult, statusResult] = await Promise.allSettled([
        api.getBasicPolicy(device.id),
        api.getCallRuntimeStatus(device.id),
      ]);
      if (!active) return;
      if (policyResult.status === "fulfilled") {
        setNumbers(policyResult.value.policy.call_allowlist);
        setContactsOnlyCalls(policyResult.value.policy.contacts_only_calls);
        setCallScreeningEnabled(policyResult.value.policy.call_screening_enabled);
      } else {
        setMessage("读取电话策略失败");
      }
      if (statusResult.status === "fulfilled") setRuntimeStatus(statusResult.value);
    };
    void refresh();
    const timer = window.setInterval(() => {
      api.getCallRuntimeStatus(device.id).then((status) => {
        if (active) setRuntimeStatus(status);
      }).catch(() => undefined);
    }, 10_000);
    return () => { active = false; window.clearInterval(timer); };
  }, [device.id]);

  const addNumber = () => {
    const normalized = newNumber.replace(/[\s()-]/g, "");
    if (!/^\+?\d{3,20}$/.test(normalized)) {
      setMessage("请输入有效的电话号码");
      return;
    }
    if (numbers.includes(normalized)) {
      setMessage("这个号码已经在白名单中");
      return;
    }
    setNumbers((current) => [...current, normalized]);
    setNewNumber("");
    setAdding(false);
    setMessage("");
  };

  const save = async () => {
    setSaving(true);
    setMessage("");
    try {
      const { policy } = await api.getBasicPolicy(device.id);
      await api.updateBasicPolicy(device.id, {
        ...policy,
        call_allowlist: numbers,
        contacts_only_calls: contactsOnlyCalls,
        call_screening_enabled: contactsOnlyCalls || callScreeningEnabled,
      });
      setMessage("白名单已提交，等待被管控端轮询生效");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "保存白名单失败");
    } finally {
      setSaving(false);
    }
  };

  const roleLabel = runtimeStatus == null
    ? "等待手机状态"
    : runtimeStatus.call_screening_role_available === false
      ? "系统不支持"
      : runtimeStatus.call_screening_role_held === true ? "已启用" : "手机需确认";
  const contactsPermissionLabel = runtimeStatus == null
    ? "等待手机状态"
    : runtimeStatus.contacts_permission_granted === true ? "已授权" : "未授权";
  const roleReady = runtimeStatus?.call_screening_role_held === true;

  return <>
    <PageHeader eyebrow="TELECOM SAFETY" title="电话白名单" description="Android 系统角色未启用时，系统不会把来电交给应用筛选。设备端在前台时会提示授权；紧急号码始终放行。" action={<button className="primary-button" onClick={() => void save()} disabled={saving}>{saving ? "保存中…" : "保存电话策略"}<Save size={16} /></button>} />
    <section className="content-grid two-one">
      <div className="panel">
        <div className="panel-title"><div><span className="section-kicker">CALL SCREENING</span><h2>设备实际状态</h2></div><StatusPill status={runtimeStatus == null ? "pending" : roleReady ? "applied" : "failed"} /></div>
        <div className="call-hero"><span className="call-icon"><Phone size={22} /></span><div><strong>{contactsOnlyCalls ? "仅允许通讯录和白名单" : "非白名单来电限制"}</strong><p>{contactsOnlyCalls ? "紧急号码、电话白名单和设备通讯录中的号码可以呼入。" : callScreeningEnabled ? "紧急号码和电话白名单可以呼入。" : "来电筛选已关闭。"}</p></div></div>
        <div className="call-rule"><span>仅允许通讯录来电</span><button className={contactsOnlyCalls ? "toggle active" : "toggle"} aria-pressed={contactsOnlyCalls} onClick={() => { const enabled = !contactsOnlyCalls; setContactsOnlyCalls(enabled); if (enabled) setCallScreeningEnabled(true); }}><span /></button></div>
        <div className="call-rule"><span>系统来电筛选角色</span><strong>{roleLabel}</strong></div>
        <div className="call-rule"><span>通讯录读取权限</span><strong>{contactsPermissionLabel}</strong></div>
        <div className="call-rule"><span>系统回调 / 拒接</span><strong>{runtimeStatus ? `${runtimeStatus.screened_call_count ?? 0} / ${runtimeStatus.blocked_call_count ?? 0}` : "尚无回报"}</strong></div>
        <div className="call-rule"><span>最近一次回调</span><strong>{runtimeStatus?.last_screened_call_at ? formatTime(runtimeStatus.last_screened_call_at) : "尚未收到"}</strong></div>
        <p className="muted-text">联系人号码只在手机本地匹配，不会上传。手机每 10 秒上报权限和筛选事件；若显示“系统不支持”，该 HyperOS 版本没有向应用开放筛选角色。</p>
      </div>
      <div className="panel">
        <div className="panel-title"><div><span className="section-kicker">ALLOWLIST</span><h2>号码清单</h2></div><span className="muted-count">{numbers.length} 个号码</span></div>
        <div className="number-list">{numbers.map((number) => <div className="number-row" key={number}><Phone size={15} /><code>{number}</code><button className="icon-button" title="移除" onClick={() => setNumbers(numbers.filter((item) => item !== number))}><X size={15} /></button></div>)}{adding ? <div className="number-add-form"><Phone size={15} /><input autoFocus inputMode="tel" placeholder="输入手机号或联系人号码" value={newNumber} onChange={(event) => setNewNumber(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") addNumber(); if (event.key === "Escape") { setAdding(false); setNewNumber(""); } }} /><button className="icon-button" title="确认添加" onClick={addNumber}><Check size={16} /></button><button className="icon-button" title="取消" onClick={() => { setAdding(false); setNewNumber(""); }}><X size={16} /></button></div> : <button className="add-row" onClick={() => { setAdding(true); setMessage(""); }}><span>+</span>添加联系人号码</button>}</div>
        {message && <div className="inline-feedback">{message}</div>}
      </div>
    </section>
  </>;
}

const SYSTEM_SETTING_KEYS = ["screen_brightness", "screen_brightness_mode", "screen_off_timeout_ms", "force_audible_ringer", "force_audible_ringer_periods", "auto_time_enabled", "auto_time_zone_enabled", "time_zone", "stay_awake_while_plugged_in"];

function SystemSettingsView({ device }: { device: Device }) {
  const [settings, setSettings] = useState<OwnerSetting[] | null>(null);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  useEffect(() => { api.getOwnerPolicy(device.id).then((result) => setSettings(result.settings.filter((item) => SYSTEM_SETTING_KEYS.includes(item.key)))); }, [device.id]);
  if (!settings) return <Loading />;
  const get = (key: string) => settings.find((item) => item.key === key);
  const value = (key: string) => get(key)?.value;
  const periodValue = value("force_audible_ringer_periods");
  const ringerPeriods = Array.isArray(periodValue) ? periodValue.map(String) : [];
  const update = (key: string, next: SettingValue) => setSettings((current) => current?.map((item) => item.key === key ? { ...item, value: next, status: "pending" } : item) ?? current);
  const save = async () => {
    setSaving(true); setMessage("");
    try {
      await api.updateOwnerPolicy(device.id, settings.filter((item) => item.supported).map(({ key, value: next }) => ({ key, value: next })));
      setMessage("系统设置已提交，等待设备轮询确认");
    } catch (caught) { setMessage(caught instanceof Error ? caught.message : "保存系统设置失败"); }
    finally { setSaving(false); }
  };
  return <><PageHeader eyebrow="ANDROID SYSTEM SETTINGS" title="系统设置" description="通过 Android Device Owner 公开接口修改 HyperOS 的显示、电源、时间和时区设置。设备不支持的项目不会下发。" action={<button className="primary-button" onClick={() => void save()} disabled={saving}><Save size={16} />{saving ? "保存中…" : "应用系统设置"}</button>} />
    {message && <div className="success-strip"><Check size={16} />{message}</div>}
    <section className="system-settings-grid">
      <div className="system-settings-section"><div className="owner-section-head"><div><span className="section-kicker">DISPLAY</span><h2>显示与息屏</h2></div><SlidersHorizontal size={18} /></div><div className="system-controls">
        <SystemControl title="屏幕亮度" description="手动亮度模式下使用，范围 1 到 255。"><div className="brightness-control"><input type="range" min="1" max="255" value={Number(value("screen_brightness") ?? 128)} disabled={value("screen_brightness_mode") === "automatic"} onChange={(event) => update("screen_brightness", Number(event.target.value))} /><output>{Number(value("screen_brightness") ?? 128)}</output></div></SystemControl>
        <SystemControl title="自动亮度" description="由环境光传感器自动调节屏幕亮度。"><button className={value("screen_brightness_mode") === "automatic" ? "toggle active" : "toggle"} aria-pressed={value("screen_brightness_mode") === "automatic"} onClick={() => update("screen_brightness_mode", value("screen_brightness_mode") === "automatic" ? "manual" : "automatic")}><span /></button></SystemControl>
        <SystemControl title="自动息屏" description="设备无操作后关闭屏幕的等待时间。"><select className="setting-select" value={Number(value("screen_off_timeout_ms") ?? 60000)} onChange={(event) => update("screen_off_timeout_ms", Number(event.target.value))}><option value={30000}>30 秒</option><option value={60000}>1 分钟</option><option value={120000}>2 分钟</option><option value={300000}>5 分钟</option><option value={600000}>10 分钟</option><option value={1800000}>30 分钟</option></select></SystemControl>
        <SystemControl title="充电时保持唤醒" description="连接 USB 或充电器时不自动关闭屏幕。"><button className={Number(value("stay_awake_while_plugged_in") ?? 0) > 0 ? "toggle active" : "toggle"} aria-pressed={Number(value("stay_awake_while_plugged_in") ?? 0) > 0} onClick={() => update("stay_awake_while_plugged_in", Number(value("stay_awake_while_plugged_in") ?? 0) > 0 ? 0 : 7)}><span /></button></SystemControl>
      </div></div>
      <div className="system-settings-section"><div className="owner-section-head"><div><span className="section-kicker">DATE AND TIME</span><h2>日期与时间</h2></div><Clock3 size={18} /></div><div className="system-controls">
        <SystemControl title="自动设置时间" description="使用网络提供的日期和时间。"><button className={value("auto_time_enabled") === true ? "toggle active" : "toggle"} aria-pressed={value("auto_time_enabled") === true} onClick={() => update("auto_time_enabled", value("auto_time_enabled") !== true)}><span /></button></SystemControl>
        <SystemControl title="自动设置时区" description="根据网络和位置自动选择时区。"><button className={value("auto_time_zone_enabled") === true ? "toggle active" : "toggle"} aria-pressed={value("auto_time_zone_enabled") === true} onClick={() => update("auto_time_zone_enabled", value("auto_time_zone_enabled") !== true)}><span /></button></SystemControl>
        <SystemControl title="设备时区" description="关闭自动时区后应用所选 IANA 时区。"><select className="setting-select" value={String(value("time_zone") ?? "Asia/Shanghai")} disabled={value("auto_time_zone_enabled") === true} onChange={(event) => update("time_zone", event.target.value)}><option value="Asia/Shanghai">中国标准时间</option><option value="Asia/Hong_Kong">香港时间</option><option value="Asia/Tokyo">日本标准时间</option><option value="UTC">协调世界时</option></select></SystemControl>
      </div></div>
      <div className="system-settings-section sound-settings-section"><div className="owner-section-head"><div><span className="section-kicker">CALL SOUND</span><h2>来电声音</h2></div><Volume2 size={18} /></div><div className="system-controls">
        <SystemControl title="强制来电响铃" description="禁止静音和仅震动模式，来电铃声音量保持最大；媒体与闹铃音量仍可自由调节。"><button className={value("force_audible_ringer") === true ? "toggle active" : "toggle"} aria-pressed={value("force_audible_ringer") === true} onClick={() => update("force_audible_ringer", value("force_audible_ringer") !== true)}><span /></button></SystemControl>
        <SystemControl title="禁止静音时段" description="按设备本地时间执行。空列表表示全天生效；结束时间早于开始时间时自动跨到次日。"><RingerScheduleEditor periods={ringerPeriods} onChange={(periods) => update("force_audible_ringer_periods", periods)} /></SystemControl>
      </div></div>
    </section>
    <section className="notice-band"><ShieldCheck size={18} /><div><strong>HyperOS 兼容范围</strong><p>显示与时间设置使用 Android Device Owner 公开接口；强制响铃按设备本地时间执行，由前台管控服务监听音频变化并即时恢复，10 秒轮询校正时段边界，不修改媒体或闹铃音量。</p></div></section>
  </>;
}

function SystemControl({ title, description, children }: { title: string; description: string; children: React.ReactNode }) {
  return <div className="system-control"><div><strong>{title}</strong><p>{description}</p></div><div className="system-control-input">{children}</div></div>;
}

function RingerScheduleEditor({ periods, onChange }: { periods: string[]; onChange: (periods: string[]) => void }) {
  const updatePeriod = (index: number, part: "start" | "end", next: string) => {
    const [start = "07:00", end = "09:00"] = periods[index].split("-");
    onChange(periods.map((period, current) => current === index ? `${part === "start" ? next : start}-${part === "end" ? next : end}` : period));
  };
  const addPeriod = () => {
    const lastEnd = periods.at(-1)?.split("-")[1] ?? "07:00";
    const [hour, minute] = lastEnd.split(":").map(Number);
    const nextEnd = `${String((hour + 1) % 24).padStart(2, "0")}:${String(minute || 0).padStart(2, "0")}`;
    onChange([...periods, `${lastEnd}-${nextEnd}`]);
  };
  return <div className="ringer-schedule">
    {periods.length === 0 && <span className="schedule-all-day"><Clock3 size={14} />全天生效</span>}
    {periods.map((period, index) => { const [start = "07:00", end = "09:00"] = period.split("-"); return <div className="schedule-period" key={index}><input type="time" aria-label={`时段 ${index + 1} 开始时间`} value={start} onChange={(event) => updatePeriod(index, "start", event.target.value)} /><span>至</span><input type="time" aria-label={`时段 ${index + 1} 结束时间`} value={end} onChange={(event) => updatePeriod(index, "end", event.target.value)} /><button type="button" className="icon-button" title="删除时段" onClick={() => onChange(periods.filter((_, current) => current !== index))}><X size={14} /></button></div>; })}
    <button type="button" className="schedule-add" disabled={periods.length >= 16} onClick={addPeriod}><Plus size={14} />添加时段</button>
  </div>;
}

function OwnerView({ device }: { device: Device }) {
  const [settings, setSettings] = useState<OwnerSetting[] | null>(null);
  const [version, setVersion] = useState(1);
  const [saved, setSaved] = useState("");
  useEffect(() => { api.getOwnerPolicy(device.id).then((result) => { setSettings(result.settings); setVersion(result.version); }); }, [device.id]);
  const groups = useMemo(() => settings?.reduce<Record<string, OwnerSetting[]>>((result, setting) => { (result[setting.category] ??= []).push(setting); return result; }, {}) ?? {}, [settings]);
  if (!settings) return <Loading />;
  const update = (key: string, value: SettingValue) => setSettings(settings.map((setting) => setting.key === key ? { ...setting, value, status: "pending" } : setting));
  const save = async () => { const result = await api.updateOwnerPolicy(device.id, settings.map(({ key, value }) => ({ key, value }))); setVersion(result.policy_version); setSaved("策略已签名并提交，等待设备返回实际生效状态"); setTimeout(() => setSaved(""), 4000); };
  return <>
    <PageHeader eyebrow="DEVICE OWNER POLICY" title="设备所有者控制面板" description="目标设备公开 DevicePolicyManager / UserManager 能力的完整视图。每项策略都会显示支持状态和实际生效状态。" action={<button className="primary-button" onClick={save}><Save size={16} />保存 Owner 策略</button>} />
    <div className="owner-toolbar"><div className="owner-summary"><span className="capability-ring"><ShieldCheck size={20} /></span><div><strong>Device Owner 已注册</strong><span>{device.model} · Android API {device.android_api} · 策略版本 v{version}</span></div></div><div className="owner-toolbar-meta"><span className="status-pill good"><span />设备能力已读取</span><span className="muted-text">{settings.filter((setting) => setting.supported).length}/{settings.length} 项可用</span></div></div>
    {saved && <div className="success-strip"><Check size={16} />{saved}</div>}
    <div className="owner-grid">{Object.entries(groups).map(([category, categorySettings]) => <section className="owner-section" key={category}><div className="owner-section-head"><div><span className="section-kicker">OWNER POLICY</span><h2>{category}</h2></div><span className="muted-count">{categorySettings.filter((setting) => setting.supported).length}/{categorySettings.length} 可用</span></div><div className="owner-settings">{categorySettings.map((setting) => <OwnerSettingRow key={setting.key} setting={setting} onChange={(value) => update(setting.key, value)} />)}</div></section>)}</div>
    <section className="notice-band"><TerminalSquare size={18} /><div><strong>策略边界</strong><p>这里控制 Android 公开 Device Owner 接口。HyperOS 私有设置、Recovery、Bootloader 和刷机不属于应用层所有者策略。</p></div></section>
  </>;
}

function OwnerSettingRow({ setting, onChange }: { setting: OwnerSetting; onChange: (value: SettingValue) => void }) {
  const value = setting.value;
  return <div className={!setting.supported ? "owner-setting unsupported" : "owner-setting"}><div className="setting-copy"><div><strong>{setting.label}</strong>{setting.high_risk && <span className="risk-tag">高风险</span>}{!setting.supported && <span className="unsupported-tag">不支持</span>}</div><p>{setting.description}</p><small><code>{setting.key}</code><span className={`setting-status ${setting.status}`}>{setting.status === "pending" ? "待设备确认" : "已读取"}</span></small></div>{setting.supported && setting.kind === "boolean" && <button className={value === true ? "toggle active" : "toggle"} aria-pressed={value === true} onClick={() => onChange(!value)}><span /></button>}{setting.supported && setting.kind === "integer" && <input className="setting-number" type="number" value={Number(value)} onChange={(event) => onChange(Number(event.target.value))} />}{setting.supported && setting.kind === "text" && setting.key === "network_default_mode" && <select className="setting-select" value={String(value)} onChange={(event) => onChange(event.target.value)}><option value="deny_unlisted">阻断未列出应用</option><option value="allow_all">允许全部联网</option></select>}{setting.supported && setting.kind === "text" && setting.key !== "network_default_mode" && <input className="setting-text" value={String(value)} maxLength={setting.key === "device_owner_lock_screen_info" ? 200 : undefined} placeholder={setting.key === "device_owner_lock_screen_info" ? "留空可清除锁屏提示" : undefined} onChange={(event) => onChange(event.target.value)} />}{setting.supported && setting.kind === "string_list" && <input className="setting-list" value={Array.isArray(value) ? value.join(", ") : String(value)} onChange={(event) => onChange(event.target.value.split(",").map((item) => item.trim()).filter(Boolean))} />}{!setting.supported && <span className="unavailable-mark"><Ban size={16} />不可用</span>}</div>;
}

function SecurityView() {
  const [keys, setKeys] = useState<RecoveryKey[]>([]);
  useEffect(() => { api.getRecoveryKeys().then((result) => setKeys(result.keys)); }, []);
  return <><PageHeader eyebrow="ADMIN SECURITY" title="安全与审计" description="管理员认证、恢复密钥和每次策略操作的可追溯记录。" action={<button className="secondary-button"><RotateCcw size={16} />刷新安全状态</button>} /><section className="content-grid two-one"><div className="panel"><div className="panel-title"><div><span className="section-kicker">RECOVERY KEYS</span><h2>一次性恢复密钥</h2></div><span className="status-pill warn"><span />登录后可见</span></div><div className="security-warning"><KeyRound size={17} /><span>每个密钥只能使用一次。密钥持续显示在管理员页面，请保护当前管理员会话。</span></div><div className="recovery-list">{keys.map((key) => <div className={key.used ? "recovery-row used" : "recovery-row"} key={key.id}><FileKey2 size={16} /><code>{key.value}</code><span>{key.used ? "已使用" : "可使用"}</span><button className="icon-button" title="复制恢复密钥" onClick={() => navigator.clipboard?.writeText(key.value)}><Copy size={15} /></button></div>)}</div></div><div className="panel"><div className="panel-title"><div><span className="section-kicker">AUTHENTICATION</span><h2>管理员认证</h2></div><ShieldCheck size={18} /></div><div className="auth-status"><div><span>管理员账号</span><strong>admin</strong></div><div><span>密码策略</span><strong>Argon2id</strong></div><div><span>二次验证</span><strong>TOTP 已启用</strong></div><div><span>高风险操作</span><strong>需要重新验证</strong></div></div></div></section><section className="panel"><div className="panel-title"><div><span className="section-kicker">AUDIT TRAIL</span><h2>审计记录</h2></div><span className="muted-count">最近 100 条</span></div><AuditTable /></section></>;
}

function AuditTable({ compact = false }: { compact?: boolean }) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  useEffect(() => { api.getAudit().then((result) => setEvents(result.events)); }, []);
  return <div className="audit-list">{events.slice(0, compact ? 4 : 100).map((event) => <div className="audit-row" key={event.id}><span className="audit-icon"><Activity size={15} /></span><div><strong>{event.message}</strong><small>{event.event} · {event.target.slice(0, 12)}</small></div><time>{formatTime(event.at)}</time></div>)}{events.length === 0 && <EmptyState icon={Database} title="暂无审计记录" text="设备和管理员操作会记录在这里。" />}</div>;
}

function EmptyState({ icon: Icon, title, text }: { icon: typeof Database; title: string; text: string }) { return <div className="empty-state"><Icon size={24} /><strong>{title}</strong><span>{text}</span></div>; }
function Loading() { return <div className="loading-state"><span className="spinner" />正在读取设备策略…</div>; }
function formatTime(value: string) { return new Intl.DateTimeFormat("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }).format(new Date(value)); }

function generateTotpSecret() {
  const bytes = new Uint8Array(20);
  globalThis.crypto.getRandomValues(bytes);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let buffer = 0;
  let bits = 0;
  let secret = "";
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      secret += alphabet[(buffer >> bits) & 31];
    }
  }
  if (bits > 0) secret += alphabet[(buffer << (5 - bits)) & 31];
  return secret;
}

createRoot(document.getElementById("root")!).render(<App />);
