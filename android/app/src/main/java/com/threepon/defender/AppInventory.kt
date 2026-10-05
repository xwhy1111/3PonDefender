package com.threepon.defender

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

/**
 * Creates the small, deterministic application inventory sent to the control
 * service.  No application data, notification content or network payload is
 * collected; only package metadata needed by the administrator is included.
 */
object AppInventory {
    private const val MAX_PERMISSIONS = 64

    data class Snapshot(
        val revision: String,
        val apps: JSONArray,
    )

    fun collect(context: Context): Snapshot {
        val packageManager = context.packageManager
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES
        val packages = packageManager.getInstalledPackages(flags)
            .sortedBy { it.packageName }
        val blocked = context.getSharedPreferences(POLICY_PREFS, Context.MODE_PRIVATE)
            .getStringSet(NETWORK_BLOCKED_PACKAGES, emptySet())
            .orEmpty()
        val controller = DeviceOwnerController(context)
        val rows = JSONArray()
        packages.forEach { packageInfo ->
            rows.put(toJson(context, packageManager, packageInfo, blocked, controller))
        }
        val canonical = rows.toString().toByteArray(Charsets.UTF_8)
        return Snapshot(sha256(canonical), rows)
    }

    private fun toJson(
        context: Context,
        packageManager: PackageManager,
        packageInfo: PackageInfo,
        blocked: Set<String>,
        controller: DeviceOwnerController,
    ): JSONObject {
        val appInfo = packageInfo.applicationInfo
        val packageName = packageInfo.packageName
        val isSystem = appInfo != null && (appInfo.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
        val isSuspended = appInfo != null && (appInfo.flags and ApplicationInfo.FLAG_SUSPENDED) != 0
        val label = runCatching {
            appInfo?.let { packageManager.getApplicationLabel(it).toString() }
        }.getOrNull().orEmpty().ifBlank { packageName }
        val signatures = if (Build.VERSION.SDK_INT >= 28) {
            packageInfo.signingInfo?.apkContentsSigners.orEmpty()
        } else {
            emptyArray()
        }
        val requestedPermissions = packageInfo.requestedPermissions.orEmpty()
        val requestedFlags = packageInfo.requestedPermissionsFlags ?: intArrayOf()
        val permissionDetails = JSONArray()
        requestedPermissions.take(MAX_PERMISSIONS).forEachIndexed { index, permission ->
            val info = runCatching { packageManager.getPermissionInfo(permission, 0) }.getOrNull()
            val protection = info?.protectionLevel?.and(PermissionInfo.PROTECTION_MASK_BASE)
            val runtime = protection == PermissionInfo.PROTECTION_DANGEROUS
            val policyState = if (runtime) controller.permissionGrantState(packageName, permission) else android.app.admin.DevicePolicyManager.PERMISSION_GRANT_STATE_DEFAULT
            val granted = requestedFlags.getOrNull(index)?.and(0x2) != 0
            permissionDetails.put(JSONObject().apply {
                put("name", permission)
                put("label", info?.loadLabel(packageManager)?.toString()?.take(80) ?: permission.substringAfterLast('.'))
                put("runtime", runtime)
                put("controllable", runtime && (appInfo?.targetSdkVersion ?: 0) >= Build.VERSION_CODES.M && packageName != context.packageName)
                put("granted", granted)
                put("grant_state", when (policyState) {
                    android.app.admin.DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED -> "granted"
                    android.app.admin.DevicePolicyManager.PERMISSION_GRANT_STATE_DENIED -> "denied"
                    else -> "default"
                })
            })
        }

        return JSONObject().apply {
            put("package_name", packageName)
            put("label", label)
            put("version_name", packageInfo.versionName ?: "")
            put("version_code", packageInfo.longVersionCode)
            put("uid", appInfo?.uid ?: -1)
            put("system_app", isSystem)
            put("enabled", appInfo?.enabled == true)
            put("suspended", isSuspended)
            put("hidden", controller.isPackageHidden(packageName))
            put("network_blocked", blocked.contains(packageName))
            put("installer", runCatching {
                if (Build.VERSION.SDK_INT >= 30) packageManager.getInstallSourceInfo(packageName).installingPackageName else null
            }.getOrNull() ?: JSONObject.NULL)
            put("signer_sha256", signatures.firstOrNull()?.let { sha256(it.toByteArray()) } ?: "")
            put("target_sdk", appInfo?.targetSdkVersion ?: 0)
            put("permissions", JSONArray(requestedPermissions.take(MAX_PERMISSIONS)))
            put("permission_details", permissionDetails)
        }
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private const val POLICY_PREFS = "policy"
    private const val NETWORK_BLOCKED_PACKAGES = "network_blocked_packages"
}
