package com.threepon.defender

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build
import android.util.Log

class UpdateInstallReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE).orEmpty()
        val preferences = context.getSharedPreferences("threepon_update", Context.MODE_PRIVATE)
        val versionCode = preferences.getLong("installing_version_code", 0L)
        val pending = goAsync()
        Thread {
            try {
                val config = PairingStore(context.applicationContext).read()
                if (status == PackageInstaller.STATUS_SUCCESS) {
                    Log.i(TAG, "3Pon Defender 更新安装成功 v$versionCode")
                    preferences.edit()
                        .putLong("last_installed_version_code", versionCode)
                        .remove("installing_version_code")
                        .remove("installing_started_at")
                        .apply()
                    if (config != null) DefenderUpdateStatusReporter.report(context, config, "applied", versionCode)
                } else {
                    if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
                        val confirmation = pendingUserAction(intent)
                        if (confirmation != null) {
                            confirmation.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            runCatching { context.startActivity(confirmation) }
                                .onSuccess { Log.w(TAG, "系统要求确认更新安装，已打开确认页面") }
                                .onFailure { Log.w(TAG, "无法打开更新确认页面", it) }
                            if (config != null) DefenderUpdateStatusReporter.report(context, config, "pending_user_action", versionCode, "系统要求确认安装")
                        } else {
                            reportFailure(context, config, preferences, versionCode, "系统要求用户确认安装，但没有返回确认 Intent")
                        }
                    } else {
                        reportFailure(context, config, preferences, versionCode, "PackageInstaller status=$status ${message.ifBlank { "无返回原因" }}")
                    }
                }
            } finally {
                runCatching { DeviceOwnerController(context.applicationContext).restorePackageInstallRestrictions() }
                pending.finish()
            }
        }.start()
    }

    private fun reportFailure(context: Context, config: PairingConfig?, preferences: android.content.SharedPreferences, versionCode: Long, detail: String) {
        Log.w(TAG, "3Pon Defender 更新安装失败: $detail")
        preferences.edit()
            .remove("installing_version_code")
            .remove("installing_started_at")
            .apply()
        if (config != null) DefenderUpdateStatusReporter.report(context, config, "failed", versionCode, detail)
    }

    @Suppress("DEPRECATION")
    private fun pendingUserAction(intent: Intent): Intent? = if (Build.VERSION.SDK_INT >= 33) {
        intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
    } else {
        intent.getParcelableExtra(Intent.EXTRA_INTENT)
    }

    companion object {
        private const val TAG = "3PonDefenderUpdate"
    }
}
