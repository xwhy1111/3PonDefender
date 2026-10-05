# Xiaomi 14 小范围 Device Owner 初始化

这是开发和小范围自用流程，不是公开发行版的用户安装流程。

## 前置条件

- 设备为 Android 16 / HyperOS 目标测试版本。
- 设备完成备份，接受恢复出厂或清除已有账号的风险。
- Android SDK Platform Tools 已安装，`adb devices` 能看到设备。
- 设备端安装 3Pon Defender debug APK。

## 注册

确认包名和 receiver 组件后执行：

```bash
adb shell dpm set-device-owner \
  com.threepon.defender/.DefenderDeviceAdminReceiver
```

如果系统拒绝注册，先检查设备是否存在已登录账号、已有工作资料、旧 Device Admin 或厂商限制。不要用普通应用模式替代 Device Owner，因为那无法保证安装拦截和防卸载。

## 注册后检查

```bash
adb shell dumpsys device_policy
adb shell settings get global development_settings_enabled
adb shell pm list packages | grep com.threepon.defender
```

打开 3Pon Defender，完成设备端功能说明和用户同意。管理员在管控台点击“绑定新设备”生成二维码，手机扫描并确认二维码中显示的服务器地址后完成绑定。二维码一次性使用且默认 10 分钟过期。

二维码中的地址必须是手机能访问的管理台 origin，包括协议、主机和端口。不要从电脑的 `localhost` 或 `127.0.0.1` 页面生成给手机使用；应使用局域网 IP 或可访问域名。

## 完成绑定后

- 由 Owner 策略关闭 USB 调试和开发者功能。
- 重新启动设备。
- 验证浏览器、文件管理器和应用商店不能直接安装 APK。
- 验证批准的 APK 只能由 DPC 安装。
- 验证 3Pon Defender 的卸载入口被阻止。
- 验证 VPN、电话筛选和 Owner 面板中的能力上报。
- 验证设备在绑定后能从配对服务器读取更新清单。
- 发布高版本 APK，验证清单签名、APK SHA-256、签名证书和 PackageInstaller 自动更新流程。

## 退出和故障处理

恢复出厂、Recovery 清除或刷机可能绕过系统层限制。发生这种情况后，服务器应将设备标记为失联，重新注册 Device Owner 并重新配对，不能把旧设备身份直接视为可信。
