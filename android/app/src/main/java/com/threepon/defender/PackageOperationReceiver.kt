package com.threepon.defender

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.util.Log

/** Receives asynchronous results from Device Owner initiated package actions. */
class PackageOperationReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE).orEmpty()
        val packageName = intent.getStringExtra(EXTRA_PACKAGE_NAME).orEmpty()
        val commandId = intent.getStringExtra(EXTRA_COMMAND_ID).orEmpty()
        val resultStatus = if (status == PackageInstaller.STATUS_SUCCESS) "applied" else "failed"
        if (status == PackageInstaller.STATUS_SUCCESS) Log.i(TAG, "应用操作成功: $packageName")
        else Log.w(TAG, "应用操作失败: $packageName status=$status $message")

        if (commandId.isBlank()) return
        val pending = goAsync()
        Thread {
            try {
                PairingStore(context.applicationContext).read()?.let { config ->
                    val detail = if (status == PackageInstaller.STATUS_SUCCESS) null else "PackageInstaller status=$status ${message.ifBlank { "无返回原因" }}"
                    DefenderCommandAckReporter.report(context.applicationContext, config, commandId, resultStatus, detail)
                }
            } finally {
                pending.finish()
            }
        }.start()
    }

    companion object {
        const val EXTRA_OPERATION = "threepon.operation"
        const val EXTRA_PACKAGE_NAME = "threepon.package_name"
        const val EXTRA_COMMAND_ID = "threepon.command_id"
        const val OP_UNINSTALL = "uninstall"
        private const val TAG = "3PonDefenderApps"
    }
}
