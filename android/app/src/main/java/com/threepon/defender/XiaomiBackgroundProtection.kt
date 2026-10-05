package com.threepon.defender

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings

/**
 * Xiaomi's autostart and task-lock controls are private Security Center
 * screens.  There is no public Android API that can silently grant them, so
 * the app only opens the matching user-facing screen and reports the standard
 * battery-optimization state.  The fallbacks keep the flow usable across
 * HyperOS regional builds where the component name differs.
 */
object XiaomiBackgroundProtection {
    fun isXiaomi(): Boolean = Build.MANUFACTURER.equals("Xiaomi", ignoreCase = true) || Build.BRAND.equals("Redmi", ignoreCase = true) || Build.BRAND.equals("POCO", ignoreCase = true)

    fun isBatteryUnrestricted(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return true
        val power = context.getSystemService(PowerManager::class.java)
        return power?.isIgnoringBatteryOptimizations(context.packageName) == true
    }

    fun openAutoStartSettings(context: Context): Boolean {
        val intents = listOf(
            Intent("miui.intent.action.OP_AUTO_START").apply {
                setPackage("com.miui.securitycenter")
                putExtra("packageName", context.packageName)
            },
            Intent().setComponent(ComponentName("com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity")),
            appDetailsIntent(context),
        )
        return startFirstResolvable(context, intents)
    }

    fun openBatterySettings(context: Context): Boolean {
        val intents = buildList {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                add(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:${context.packageName}")))
            }
            add(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
            add(appDetailsIntent(context))
        }
        return startFirstResolvable(context, intents)
    }

    private fun appDetailsIntent(context: Context): Intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${context.packageName}"))

    private fun startFirstResolvable(context: Context, intents: List<Intent>): Boolean {
        val packageManager = context.packageManager
        for (intent in intents) {
            if (intent.resolveActivity(packageManager) != null) {
                runCatching { context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }.onSuccess { return true }
            }
        }
        return false
    }
}
