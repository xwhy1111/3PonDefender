package com.threepon.defender

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.content.pm.ServiceInfo
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * A local discard VPN used for selected application network blocks.
 *
 * Android's public Device Owner API does not expose a per-package firewall.
 * VpnService does expose per-application routing, so blocked packages are
 * routed into this interface and every packet is consumed without forwarding.
 * Other applications are not routed through it. This deliberately does not
 * inspect, proxy or decrypt traffic.
 */
class DefenderVpnService : VpnService() {
    private val serviceJob = SupervisorJob()
    private val scope = CoroutineScope(Dispatchers.IO + serviceJob)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var readerJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification("正在应用联网限制"), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification("正在应用联网限制"))
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        reconfigure()
        return START_STICKY
    }

    private fun reconfigure() {
        val blocked = DeviceOwnerController(applicationContext).networkBlockedPackages()
            .filter { it.isNotBlank() && it != applicationContext.packageName }
            .distinct()
        closeInterface()
        if (blocked.isEmpty()) {
            stopSelf()
            return
        }

        val builder = Builder()
            .setSession("3Pon Defender 应用联网限制")
            .setMtu(1500)
            .addAddress("10.88.0.2", 32)
            .addRoute("0.0.0.0", 0)
        val routed = blocked.count { packageName ->
            runCatching {
                builder.addAllowedApplication(packageName)
                true
            }.getOrDefault(false)
        }
        if (routed == 0) {
            stopSelf()
            return
        }
        vpnInterface = runCatching { builder.establish() }
            .getOrElse {
                stopSelf()
                return
            }
        val activeInterface = vpnInterface ?: return
        updateNotification("已阻止 $routed 个应用联网")
        readerJob = scope.launch {
            val buffer = ByteArray(32 * 1024)
            runCatching {
                ParcelFileDescriptor.AutoCloseInputStream(activeInterface).use { input ->
                    while (isActive && input.read(buffer) >= 0) {
                        // Deliberately discard packets. No traffic body is stored.
                    }
                }
            }
        }
    }

    private fun closeInterface() {
        readerJob?.cancel()
        readerJob = null
        vpnInterface?.close()
        vpnInterface = null
    }

    override fun onDestroy() {
        closeInterface()
        serviceJob.cancel()
        super.onDestroy()
    }

    override fun onRevoke() {
        closeInterface()
        super.onRevoke()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            getSystemService(NotificationManager::class.java).createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "3Pon Defender 联网限制", NotificationManager.IMPORTANCE_LOW),
            )
        }
    }

    private fun notification(text: String): Notification = NotificationCompat.Builder(this, CHANNEL_ID)
        .setSmallIcon(android.R.drawable.stat_sys_warning)
        .setContentTitle("3Pon Defender")
        .setContentText(text)
        .setOngoing(true)
        .build()

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification(text))
    }

    companion object {
        private const val CHANNEL_ID = "threepon_network_block"
        private const val NOTIFICATION_ID = 3017

        fun start(context: Context) {
            val intent = Intent(context, DefenderVpnService::class.java)
            if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(intent) else context.startService(intent)
        }

        fun refresh(context: Context) {
            val hasBlocked = DeviceOwnerController(context).networkBlockedPackages().isNotEmpty()
            if (hasBlocked) start(context) else stop(context)
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, DefenderVpnService::class.java))
        }
    }
}
