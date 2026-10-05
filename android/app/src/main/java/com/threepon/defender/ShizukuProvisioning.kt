package com.threepon.defender

import android.app.Activity
import android.content.ComponentName
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.IBinder
import rikka.shizuku.Shizuku

object ShizukuProvisioning {
    const val REQUEST_CODE = 3016

    fun isAvailable(): Boolean = runCatching { Shizuku.pingBinder() }.getOrDefault(false)

    fun register(activity: Activity, onResult: (String) -> Unit) {
        if (!isAvailable()) {
            onResult("未检测到 Shizuku，请先安装并启动 Shizuku")
            return
        }
        if (Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
            Shizuku.requestPermission(REQUEST_CODE)
            onResult("请在 Shizuku 中授权 3Pon Defender，然后再次点击注册")
            return
        }
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                runCatching {
                    val command = arrayOf("dpm", "set-device-owner", "--user", "0", "${activity.packageName}/.DefenderDeviceAdminReceiver")
                    val output = IShizukuCommand.Stub.asInterface(service).exec(command)
                    if (output.startsWith("exit=0")) "Device Owner 注册命令已执行，请返回页面刷新状态" else "系统拒绝注册：$output"
                }.onFailure { onResult("Shizuku 执行失败：${it.message}") }.onSuccess(onResult)
                runCatching { Shizuku.unbindUserService(userServiceArgs(activity), this, true) }
            }

            override fun onServiceDisconnected(name: ComponentName) {
                onResult("Shizuku 服务已断开")
            }
        }
        runCatching { Shizuku.bindUserService(userServiceArgs(activity), connection) }
            .onFailure { onResult("Shizuku 服务启动失败：${it.message}") }
    }

    private fun userServiceArgs(activity: Activity) = Shizuku.UserServiceArgs(
        ComponentName(activity, ShizukuCommandService::class.java),
    ).daemon(false).debuggable(BuildConfig.DEBUG).version(1)
}
