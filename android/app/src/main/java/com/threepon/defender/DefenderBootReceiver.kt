package com.threepon.defender

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class DefenderBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val restartActions = setOf(
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_LOCKED_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED,
        )
        if (intent.action in restartActions) {
            if (PairingStore(context.applicationContext).read() != null) {
                runCatching { DefenderPollingService.start(context) }
                    .onFailure { Log.w(TAG, "开机恢复轮询服务失败", it) }
                DefenderUpdateScheduler.schedule(context)
                DefenderUpdateScheduler.checkNow(context)
            }
        }
    }

    companion object {
        private const val TAG = "3PonDefenderBoot"
    }
}
