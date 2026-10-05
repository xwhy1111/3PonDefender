# 3Pon Defender

3Pon Defender is a small-scope, consent-based Android Device Owner controller. It has two management surfaces:

- **Basic controls** for application approvals, application network policy and traffic metadata, remote uninstall, app suspension, call screening, self-protection, pairing and administrator security.
- **Device Owner controls** for the public Android `DevicePolicyManager` and `UserManager` policy surface supported by the enrolled device.

The repository is intentionally split into three deployable parts:

```text
server_fastapi/ FastAPI control service and HTTP polling device gateway
server/   Legacy Rust Axum service retained for reference
web/      React/TypeScript administrator workbench
android/  Kotlin Android Device Owner client
```

## Local development

首次启动时 FastAPI 服务没有管理员账号，管理台会强制进入初始化页面。管理员需要创建用户名和至少 9 位密码，并用认证器扫描页面生成的 TOTP 二维码，再输入当前 OTP 完成初始化。管理员配置和一次性恢复密钥会保存到 `THREEPON_STATE_PATH` 指定的持久化文件中；设置完成后每次登录都必须使用真实 TOTP。

```bash
uvicorn server_fastapi.main:app --host 0.0.0.0 --port 8015
```

In a second terminal:

```bash
cd web
npm install
VITE_MOCK=true npm run dev
```

The API is served at `http://localhost:8080`, and the Vite workbench at `http://localhost:5173`. Set `VITE_MOCK=false` after starting the Rust service to use live API data.

## QR 配对与自动更新

登录管理台后，点击右上角“绑定新设备”。二维码会由管控端生成，内容包含一次性配对票据、服务器 Ed25519 公钥、更新清单地址和浏览器当前的 `window.location.origin`。因此 `baseUrl` 会自动包含用户实际访问管理台的协议、域名/IP 和端口，被管控端不再提供 URL 输入框。

不要在电脑上用 `localhost` 或 `127.0.0.1` 打开管理台后给手机扫码；回环地址只对当前电脑有效。请用局域网 IP 或手机可访问的域名打开管理台，界面会显示当前地址并在回环地址时提示修正。

配对前，被管控端必须完成 Device Owner 注册并明确同意功能说明。二维码 只能 claim 一次，默认 10 分钟过期。设备凭据使用 Android Keystore 加密保存，重新绑定只能通过扫描新的二维码完成。

自动更新由被管控端前台服务每 10 秒轮询配置和更新清单；开机后自动恢复。发现更高版本后仍会执行清单 Ed25519 签名、包名、版本号、下载地址同源性、APK SHA-256、APK 签名证书以及当前安装版本签名证书校验，任一校验失败都保留当前版本。WorkManager 只作为低频兜底调度，不承担 10 秒周期。

release APK 只接受 HTTPS 配对二维码和更新地址；debug APK 为局域网实机测试保留 HTTP 支持。二维码中的地址必须是浏览器当前访问管理台的 origin（协议、主机和端口），不包含路径、查询参数或片段。

生产环境必须持久化 `THREEPON_POLICY_SIGNING_KEY`（base64 编码的 32 字节 Ed25519 seed）。如果服务端重启时更换该密钥，已绑定设备会拒绝新的更新清单，必须重新配对。

HTTPS 生产环境建议通过 Caddy 反向代理部署，并把 `THREEPON_PUBLIC_BASE_URL` 设置为用户实际访问的 HTTPS origin。当前 LAN Compose 部署由 Caddy 对外监听 `8015`，再转发到 Compose 内网的 FastAPI 服务；设备只使用普通 HTTP 请求，因此反向代理不需要 WebSocket 支持。开发环境可以使用 HTTP，但必须让手机能访问运行 Caddy 的主机和端口。

## Android provisioning

The Android project targets SDK 36 and contains the Device Admin receiver, Compose onboarding screen, policy applier, VPN service boundary, and call screening service. For the small-scope Xiaomi 14 test flow, install the debug APK and register the receiver with ADB after a clean device setup. Disable USB debugging after enrollment.

Device Owner does not equal root. Shizuku can, after explicit user authorization, execute the system `dpm set-device-owner` command as a convenience; it cannot bypass Android's account, user, work-profile, or existing-owner checks. After registration, policy control uses `DevicePolicyManager`, not Shizuku. The client reports unsupported public policies instead of claiming they were applied. Recovery, bootloader flashing, and vendor-private HyperOS settings remain outside the public Device Owner contract.

## HTTP polling and HyperOS

The FastAPI service exposes `GET /api/v1/device/poll` on port `8015`. The Android foreground service calls it every 10 seconds with `X-Device-Token`; the response contains the effective policy, queued commands, and the signed APK update manifest. Commands are confirmed with `POST /api/v1/device/command-ack`.

On Xiaomi/HyperOS, the user must explicitly allow 3Pon Defender in Auto-start and remove battery/background restrictions. Device Owner does not automatically grant those vendor-specific permissions. The persistent notification is intentional: it indicates that the 10-second foreground polling service is running. HyperOS firmware updates may change private behavior and require real-device verification.

Incoming-call filtering has two Android-side prerequisites in addition to the server policy: 3Pon Defender must hold the system `ROLE_CALL_SCREENING` role, and `READ_CONTACTS` must be granted for contact-only mode. After the user agrees to bind the device, the app requests the system call-screening role when filtering is enabled; the system still requires the user to confirm it. The phone reports role/permission state and aggregate screening counts to the administrator console, but never uploads contact records or caller numbers. If HyperOS reports that the role is unavailable, public Android APIs cannot make the service receive calls on that firmware; the console now shows that limitation instead of claiming the policy is active.

## Production notes

- Put Caddy or another TLS terminator in front of the Rust service.
- The active deployment is the FastAPI service in `server_fastapi`; PostgreSQL is not required for this small-scope deployment because the service uses an atomic JSON state file. The legacy Rust migrations are retained for reference.
- Complete administrator initialization from a trusted browser before exposing the service beyond the LAN.
- Store APK artifacts outside the web root and verify SHA-256 plus signer certificate before installation. Configure the update variables in `.env.example`.
- Keep user consent, policy changes, destructive commands, and recovery-key use in the audit log.
# 3PonDefender
