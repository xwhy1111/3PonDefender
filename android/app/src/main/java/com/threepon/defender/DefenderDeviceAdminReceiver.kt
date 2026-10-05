package com.threepon.defender

import android.app.admin.DeviceAdminReceiver
import android.content.Context
import android.content.Intent
import android.widget.Toast

class DefenderDeviceAdminReceiver : DeviceAdminReceiver() {
    override fun onEnabled(context: Context, intent: Intent) {
        Toast.makeText(context, "3Pon Defender 设备所有者已启用", Toast.LENGTH_SHORT).show()
    }

    override fun onDisabled(context: Context, intent: Intent) {
        Toast.makeText(context, "3Pon Defender 设备所有者已停用", Toast.LENGTH_SHORT).show()
    }

    companion object {
        fun component(context: Context) = android.content.ComponentName(context, DefenderDeviceAdminReceiver::class.java)
    }
}

