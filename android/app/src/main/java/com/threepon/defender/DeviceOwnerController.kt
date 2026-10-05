package com.threepon.defender

import android.Manifest
import android.app.PendingIntent
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.media.AudioManager
import android.os.Build
import android.os.UserManager
import android.provider.Settings
import java.time.LocalTime
import java.time.ZoneId
import java.util.UUID

class DeviceOwnerController(private val context: Context) {
    private val dpm = context.getSystemService(DevicePolicyManager::class.java)
    private val admin = DefenderDeviceAdminReceiver.component(context)
    private val policy = context.getSharedPreferences(POLICY_PREFS, Context.MODE_PRIVATE)

    fun isDeviceOwner(): Boolean = dpm.isDeviceOwnerApp(context.packageName)

    fun capabilities(): List<DeviceCapability> = listOf(
        capability("block_user_install", isDeviceOwner()),
        capability("block_unknown_sources", isDeviceOwner()),
        capability("defender_uninstall_blocked", isDeviceOwner()),
        capability("suspend_unapproved_apps", isDeviceOwner()),
        capability("restrict_account_changes", isDeviceOwner()),
        capability("restrict_usb_debugging", isDeviceOwner()),
        capability("restrict_developer_options", isDeviceOwner()),
        capability("camera_disabled", isDeviceOwner()),
        capability("microphone_disabled", false, "公开 Device Owner API 不提供通用麦克风禁用策略"),
        capability("screen_capture_disabled", isDeviceOwner()),
        capability("status_bar_disabled", isDeviceOwner()),
        capability("lock_task_mode", isDeviceOwner()),
        capability("always_on_vpn", isDeviceOwner()),
        capability("vpn_lockdown", isDeviceOwner()),
        capability("factory_reset_blocked", isDeviceOwner()),
        capability("auto_time_enabled", Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && isDeviceOwner()),
        capability("auto_time_zone_enabled", Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && isDeviceOwner()),
        capability("external_storage_disabled", isDeviceOwner()),
        capability("password_min_length", isDeviceOwner()),
        capability("max_time_to_lock_ms", isDeviceOwner()),
        capability("device_owner_lock_screen_info", isDeviceOwner()),
        capability("wifi_config_lockdown", isDeviceOwner()),
        capability("time_zone", isDeviceOwner()),
        capability("stay_awake_while_plugged_in", isDeviceOwner()),
        capability("screen_brightness", isDeviceOwner()),
        capability("screen_brightness_mode", isDeviceOwner()),
        capability("screen_off_timeout_ms", isDeviceOwner()),
        capability("force_audible_ringer", isDeviceOwner()),
        capability("force_audible_ringer_periods", isDeviceOwner()),
        capability("keyguard_features_restricted", isDeviceOwner()),
        capability("call_screening_enabled", true),
        capability("contacts_only_calls", true),
    )

    fun apply(key: String, value: Any): Result<Unit> = runCatching {
        val deviceOwnerRequired = key !in setOf("call_screening_enabled", "call_allowlist", "contacts_only_calls")
        if (deviceOwnerRequired) check(isDeviceOwner()) { "当前应用还不是 Device Owner" }
        when (key) {
            "block_user_install" -> setRestriction(UserManager.DISALLOW_INSTALL_APPS, value as Boolean)
            "block_unknown_sources" -> setRestriction(UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES, value as Boolean)
            "restrict_account_changes" -> setRestriction(UserManager.DISALLOW_MODIFY_ACCOUNTS, value as Boolean)
            "restrict_usb_debugging", "restrict_developer_options" -> setRestriction(UserManager.DISALLOW_DEBUGGING_FEATURES, value as Boolean)
            "factory_reset_blocked" -> setRestriction(UserManager.DISALLOW_FACTORY_RESET, value as Boolean)
            "external_storage_disabled" -> setRestriction(UserManager.DISALLOW_MOUNT_PHYSICAL_MEDIA, value as Boolean)
            "camera_disabled" -> dpm.setCameraDisabled(admin, value as Boolean)
            "screen_capture_disabled" -> dpm.setScreenCaptureDisabled(admin, value as Boolean)
            "status_bar_disabled" -> dpm.setStatusBarDisabled(admin, value as Boolean)
            "password_min_length" -> setPasswordMinimumLength((value as Number).toInt())
            "max_time_to_lock_ms" -> {
                val milliseconds = (value as Number).toLong().coerceIn(0L, MAX_TIME_TO_LOCK_MS)
                dpm.setMaximumTimeToLock(admin, milliseconds)
            }
            "device_owner_lock_screen_info" -> {
                val text = value.toString().trim()
                require(text.length <= MAX_LOCK_SCREEN_INFO_LENGTH) { "锁屏监管提示不能超过 $MAX_LOCK_SCREEN_INFO_LENGTH 个字符" }
                dpm.setDeviceOwnerLockScreenInfo(admin, text.takeIf { it.isNotBlank() })
            }
            "keyguard_features_restricted" -> {
                val enabled = value as Boolean
                // The default is NONE. On an already-provisioned device, Android
                // may retain pre-update admin metadata that lacks this optional
                // policy, so even reading NONE can throw SecurityException. A
                // disabled policy is therefore a deliberate no-op; enabling it
                // still uses the public Device Owner API and reports its error.
                if (enabled) dpm.setKeyguardDisabledFeatures(admin, DevicePolicyManager.KEYGUARD_DISABLE_FEATURES_ALL)
            }
            "lock_task_mode" -> if (value as Boolean) dpm.setLockTaskPackages(admin, arrayOf(context.packageName)) else dpm.setLockTaskPackages(admin, emptyArray())
            "auto_time_enabled" -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) dpm.setAutoTimeEnabled(admin, value as Boolean)
            "auto_time_zone_enabled" -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) dpm.setAutoTimeZoneEnabled(admin, value as Boolean)
            "defender_uninstall_blocked" -> dpm.setUninstallBlocked(admin, context.packageName, value as Boolean)
            "call_screening_enabled" -> {
                val preferences = context.getSharedPreferences("policy", Context.MODE_PRIVATE)
                val enabled = value as Boolean || preferences.getBoolean("contacts_only_calls", false)
                check(preferences.edit().putBoolean("call_screening_enabled", enabled).commit()) { "无法保存来电筛选策略" }
            }
            "call_allowlist" -> {
                val numbers = (value as List<*>).filterIsInstance<String>().toSet()
                check(context.getSharedPreferences("policy", Context.MODE_PRIVATE).edit().putStringSet("call_allowlist", numbers).commit()) {
                    "无法保存电话白名单"
                }
            }
            "contacts_only_calls" -> {
                val enabled = value as Boolean
                val preferences = context.getSharedPreferences("policy", Context.MODE_PRIVATE)
                if (enabled && context.checkSelfPermission(Manifest.permission.READ_CONTACTS) != PackageManager.PERMISSION_GRANTED && isDeviceOwner()) {
                    runCatching {
                        dpm.setPermissionGrantState(admin, context.packageName, Manifest.permission.READ_CONTACTS, DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED)
                    }
                }
                check(
                    preferences.edit()
                        .putBoolean("contacts_only_calls", enabled)
                        .putBoolean("call_screening_enabled", enabled || preferences.getBoolean("call_screening_enabled", true))
                        .commit(),
                ) { "无法保存通讯录来电策略" }
                check(!enabled || context.checkSelfPermission(Manifest.permission.READ_CONTACTS) == PackageManager.PERMISSION_GRANTED) {
                    "通讯录来电模式已启用，但读取通讯录权限尚未授予；请在手机上允许读取通讯录"
                }
            }
            "network_default_mode" -> {
                val mode = value.toString()
                require(mode == NETWORK_ALLOW_ALL || mode == NETWORK_DENY_UNLISTED) { "未知联网策略" }
                policy.edit().putString(NETWORK_DEFAULT_MODE, mode).apply()
                DefenderVpnService.refresh(context)
            }
            "always_on_vpn" -> configureAlwaysOnVpn(value as Boolean, policy.getBoolean(VPN_LOCKDOWN, false))
            "vpn_lockdown" -> configureAlwaysOnVpn(policy.getBoolean(ALWAYS_ON_VPN, false), value as Boolean)
            "suspend_unapproved_apps" -> policy.edit().putBoolean(SUSPEND_UNAPPROVED_APPS, value as Boolean).apply()
            "defender_background_protection" -> policy.edit().putBoolean(BACKGROUND_PROTECTION, value as Boolean).apply()
            "wifi_config_lockdown" -> dpm.setGlobalSetting(admin, WIFI_CONFIG_LOCKDOWN_SETTING, if (value as Boolean) "1" else "0")
            "time_zone" -> {
                val zone = value.toString()
                require(zone in ZoneId.getAvailableZoneIds()) { "无效的时区" }
                dpm.setTimeZone(admin, zone)
            }
            "stay_awake_while_plugged_in" -> {
                val flags = (value as Number).toInt().coerceIn(0, 7)
                dpm.setGlobalSetting(admin, Settings.Global.STAY_ON_WHILE_PLUGGED_IN, flags.toString())
            }
            "screen_brightness" -> {
                val brightness = (value as Number).toInt().coerceIn(MIN_BRIGHTNESS, MAX_BRIGHTNESS)
                dpm.setSystemSetting(admin, Settings.System.SCREEN_BRIGHTNESS, brightness.toString())
            }
            "screen_brightness_mode" -> {
                val mode = when (value.toString()) {
                    BRIGHTNESS_AUTOMATIC -> Settings.System.SCREEN_BRIGHTNESS_MODE_AUTOMATIC
                    BRIGHTNESS_MANUAL -> Settings.System.SCREEN_BRIGHTNESS_MODE_MANUAL
                    else -> error("未知亮度模式")
                }
                dpm.setSystemSetting(admin, Settings.System.SCREEN_BRIGHTNESS_MODE, mode.toString())
            }
            "screen_off_timeout_ms" -> {
                val timeout = (value as Number).toLong().coerceIn(MIN_SCREEN_TIMEOUT_MS, MAX_SCREEN_TIMEOUT_MS)
                dpm.setSystemSetting(admin, Settings.System.SCREEN_OFF_TIMEOUT, timeout.toString())
            }
            "force_audible_ringer" -> {
                val enabled = value as Boolean
                policy.edit().putBoolean(FORCE_AUDIBLE_RINGER, enabled).apply()
                enforceAudibleRinger()
            }
            "force_audible_ringer_periods" -> {
                val periods = (value as? List<*>)?.map { it.toString().trim() }
                    ?: error("禁止静音时段必须是列表")
                require(periods.size <= MAX_RINGER_PERIODS) { "禁止静音时段不能超过 $MAX_RINGER_PERIODS 项" }
                periods.forEach { period ->
                    val range = parseRingerPeriod(period)
                    require(range != null) { "禁止静音时段格式必须为 HH:mm-HH:mm" }
                    require(range.first != range.second) { "禁止静音时段的开始和结束时间不能相同" }
                }
                policy.edit().putStringSet(FORCE_AUDIBLE_RINGER_PERIODS, periods.toSet()).apply()
                enforceAudibleRinger()
            }
            else -> throw IllegalArgumentException("未知策略: $key")
        }
    }

    /**
     * Keep only the incoming-call stream audible. Media and alarm streams are
     * deliberately untouched so the device user can continue adjusting them.
     */
    fun enforceAudibleRinger() {
        if (!isDeviceOwner()) return
        val audio = context.getSystemService(AudioManager::class.java)
        if (audio.isVolumeFixed) return
        val shouldEnforce = policy.getBoolean(FORCE_AUDIBLE_RINGER, false) && isRingerEnforcementPeriodActive()
        val wasEnforcing = policy.getBoolean(FORCE_AUDIBLE_RINGER_ACTIVE, false)
        if (!shouldEnforce) {
            if (wasEnforcing) restorePreviousRingerState(audio)
            return
        }
        if (!wasEnforcing) {
            policy.edit()
                .putBoolean(FORCE_AUDIBLE_RINGER_ACTIVE, true)
                .putInt(PREVIOUS_RINGER_MODE, audio.ringerMode)
                .putInt(PREVIOUS_RING_VOLUME, audio.getStreamVolume(AudioManager.STREAM_RING))
                .commit()
        }
        if (audio.ringerMode != AudioManager.RINGER_MODE_NORMAL) {
            audio.ringerMode = AudioManager.RINGER_MODE_NORMAL
        }
        val maximum = audio.getStreamMaxVolume(AudioManager.STREAM_RING)
        if (maximum > 0 && audio.getStreamVolume(AudioManager.STREAM_RING) != maximum) {
            audio.setStreamVolume(AudioManager.STREAM_RING, maximum, 0)
        }
    }

    private fun isRingerEnforcementPeriodActive(now: LocalTime = LocalTime.now()): Boolean {
        val periods = policy.getStringSet(FORCE_AUDIBLE_RINGER_PERIODS, emptySet()).orEmpty()
        if (periods.isEmpty()) return true
        val currentMinute = now.hour * 60 + now.minute
        return periods.any { period ->
            val range = parseRingerPeriod(period) ?: return@any false
            if (range.first < range.second) {
                currentMinute >= range.first && currentMinute < range.second
            } else {
                currentMinute >= range.first || currentMinute < range.second
            }
        }
    }

    private fun restorePreviousRingerState(audio: AudioManager) {
        val previousMode = policy.getInt(PREVIOUS_RINGER_MODE, AudioManager.RINGER_MODE_NORMAL)
        val previousVolume = policy.getInt(PREVIOUS_RING_VOLUME, audio.getStreamVolume(AudioManager.STREAM_RING))
        policy.edit().putBoolean(FORCE_AUDIBLE_RINGER_ACTIVE, false).commit()
        runCatching {
            val safeVolume = previousVolume.coerceIn(0, audio.getStreamMaxVolume(AudioManager.STREAM_RING))
            audio.setStreamVolume(AudioManager.STREAM_RING, safeVolume, 0)
        }
        runCatching { audio.ringerMode = previousMode }
        policy.edit().remove(PREVIOUS_RINGER_MODE).remove(PREVIOUS_RING_VOLUME).apply()
    }

    private fun parseRingerPeriod(period: String): Pair<Int, Int>? {
        val match = RINGER_PERIOD_PATTERN.matchEntire(period) ?: return null
        fun minutes(hour: String, minute: String) = hour.toInt() * 60 + minute.toInt()
        return minutes(match.groupValues[1], match.groupValues[2]) to
            minutes(match.groupValues[3], match.groupValues[4])
    }

    fun permissionGrantState(packageName: String, permission: String): Int {
        if (!isDeviceOwner()) return DevicePolicyManager.PERMISSION_GRANT_STATE_DEFAULT
        return runCatching { dpm.getPermissionGrantState(admin, packageName, permission) }
            .getOrDefault(DevicePolicyManager.PERMISSION_GRANT_STATE_DEFAULT)
    }

    fun setPermissionGrantState(packageName: String, permission: String, state: String) {
        check(isDeviceOwner()) { "当前应用还不是 Device Owner" }
        rejectSelf(packageName)
        require(permission.startsWith("android.permission.")) { "仅支持 Android 运行时权限" }
        val grantState = when (state) {
            PERMISSION_ALLOW -> DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED
            PERMISSION_DENY -> DevicePolicyManager.PERMISSION_GRANT_STATE_DENIED
            PERMISSION_DEFAULT -> DevicePolicyManager.PERMISSION_GRANT_STATE_DEFAULT
            else -> error("未知权限状态")
        }
        val info = context.packageManager.getPermissionInfo(permission, 0)
        val protection = info.protectionLevel and android.content.pm.PermissionInfo.PROTECTION_MASK_BASE
        require(protection == android.content.pm.PermissionInfo.PROTECTION_DANGEROUS) { "该权限不是可管控的运行时权限" }
        check(dpm.setPermissionGrantState(admin, packageName, permission, grantState)) { "设备拒绝修改应用权限" }
    }

    fun suspendPackages(packages: List<String>, suspended: Boolean) {
        val result = suspendPackagesBestEffort(packages, suspended)
        check(result.failed.isEmpty()) {
            result.failed.entries.joinToString(prefix = "应用暂停操作失败: ", separator = "; ") { (packageName, reason) ->
                "$packageName ($reason)"
            }
        }
    }

    fun suspendPackagesBestEffort(packages: Collection<String>, suspended: Boolean): PackageSuspensionResult {
        check(isDeviceOwner()) { "当前应用还不是 Device Owner" }
        val succeeded = linkedSetOf<String>()
        val failed = linkedMapOf<String, String>()
        packages.map(String::trim).filter(String::isNotBlank).distinct().forEach { packageName ->
            if (packageName == context.packageName) {
                failed[packageName] = "不能暂停 3Pon Defender"
                return@forEach
            }
            val installed = runCatching { context.packageManager.getApplicationInfo(packageName, 0) }.isSuccess
            if (!installed) {
                if (suspended) failed[packageName] = "应用未安装" else succeeded += packageName
                return@forEach
            }
            runCatching {
                val rejected = dpm.setPackagesSuspended(admin, arrayOf(packageName), suspended)
                if (rejected.isEmpty()) {
                    succeeded += packageName
                } else {
                    failed[packageName] = "Android/HyperOS 不允许暂停该系统关键应用"
                }
            }.onFailure { error ->
                failed[packageName] = error.message?.take(180) ?: error.javaClass.simpleName
            }
        }
        return PackageSuspensionResult(succeeded, failed)
    }

    fun suspendPackage(packageName: String, suspended: Boolean) {
        rejectSelf(packageName)
        suspendPackages(listOf(packageName), suspended)
    }

    fun hidePackage(packageName: String, hidden: Boolean) {
        check(isDeviceOwner()) { "当前应用还不是 Device Owner" }
        rejectSelf(packageName)
        dpm.setApplicationHidden(admin, packageName, hidden)
    }

    fun isPackageHidden(packageName: String): Boolean =
        isDeviceOwner() && runCatching { dpm.isApplicationHidden(admin, packageName) }.getOrDefault(false)

    /**
     * PackageInstaller is used only after the server has authenticated the
     * administrator and queued a command. Android still performs the final
     * package/signature/user checks. The receiver reports the asynchronous
     * result while the next inventory confirms the final state.
     */
    fun uninstallPackage(packageName: String, commandId: String? = null) {
        check(isDeviceOwner()) { "当前应用还不是 Device Owner" }
        rejectSelf(packageName)
        val requestCode = UUID.randomUUID().hashCode()
        val callback = PendingIntent.getBroadcast(
            context,
            requestCode,
            Intent(context, PackageOperationReceiver::class.java).apply {
                putExtra(PackageOperationReceiver.EXTRA_OPERATION, PackageOperationReceiver.OP_UNINSTALL)
                putExtra(PackageOperationReceiver.EXTRA_PACKAGE_NAME, packageName)
                if (!commandId.isNullOrBlank()) putExtra(PackageOperationReceiver.EXTRA_COMMAND_ID, commandId)
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        context.packageManager.packageInstaller.uninstall(packageName, callback.intentSender)
    }

    /**
     * Android has no public per-UID firewall API for a Device Owner. The
     * companion VpnService therefore routes selected packages into a local
     * discard interface. It is a real block for those packages and does not
     * inspect or decrypt their traffic.
     */
    fun setNetworkBlocked(packageName: String, blocked: Boolean) {
        check(isDeviceOwner()) { "当前应用还不是 Device Owner" }
        rejectSelf(packageName)
        val targets = policy.getStringSet(NETWORK_BLOCKED_PACKAGES, emptySet()).orEmpty().toMutableSet()
        if (blocked) targets += packageName else targets -= packageName
        policy.edit().putStringSet(NETWORK_BLOCKED_PACKAGES, targets).apply()
        DefenderVpnService.refresh(context)
    }

    fun networkBlockedPackages(): Set<String> =
        policy.getStringSet(NETWORK_BLOCKED_PACKAGES, emptySet()).orEmpty()

    fun setAlwaysOnVpn(vpnPackage: String, lockdown: Boolean) {
        check(isDeviceOwner()) { "当前应用还不是 Device Owner" }
        dpm.setAlwaysOnVpnPackage(admin, vpnPackage, lockdown)
    }

    /**
     * Xiaomi enforces DISALLOW_INSTALL_APPS when PackageInstaller creates an
     * update session, even for the Device Owner. Preserve the administrator's
     * restrictions, clear them only for this session, and restore them from
     * the install result receiver.
     */
    fun preparePackageInstall() {
        check(isDeviceOwner()) { "当前应用还不是 Device Owner" }
        val restrictions = dpm.getUserRestrictions(admin)
        val restoreInstall = restrictions.getBoolean(UserManager.DISALLOW_INSTALL_APPS, false)
        val restoreUnknownSources = restrictions.getBoolean(UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES, false)
        policy.edit()
            .putBoolean(TEMP_INSTALL_RESTORE_PENDING, true)
            .putBoolean(TEMP_RESTORE_INSTALL, restoreInstall)
            .putBoolean(TEMP_RESTORE_UNKNOWN_SOURCES, restoreUnknownSources)
            .apply()
        if (restoreInstall) dpm.clearUserRestriction(admin, UserManager.DISALLOW_INSTALL_APPS)
        if (restoreUnknownSources) dpm.clearUserRestriction(admin, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES)
    }

    fun restorePackageInstallRestrictions() {
        if (!policy.getBoolean(TEMP_INSTALL_RESTORE_PENDING, false)) return
        val restoreInstall = policy.getBoolean(TEMP_RESTORE_INSTALL, false)
        val restoreUnknownSources = policy.getBoolean(TEMP_RESTORE_UNKNOWN_SOURCES, false)
        runCatching {
            if (restoreInstall) dpm.addUserRestriction(admin, UserManager.DISALLOW_INSTALL_APPS)
            else dpm.clearUserRestriction(admin, UserManager.DISALLOW_INSTALL_APPS)
            if (restoreUnknownSources) dpm.addUserRestriction(admin, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES)
            else dpm.clearUserRestriction(admin, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES)
        }.also {
            policy.edit()
                .remove(TEMP_INSTALL_RESTORE_PENDING)
                .remove(TEMP_RESTORE_INSTALL)
                .remove(TEMP_RESTORE_UNKNOWN_SOURCES)
                .apply()
        }
    }

    fun applyBasicPolicy(policy: BasicControlPolicy) {
        apply("block_user_install", policy.installationApprovalRequired).getOrThrow()
        apply("block_unknown_sources", policy.installationApprovalRequired).getOrThrow()
        apply("defender_uninstall_blocked", policy.defenderSelfProtection).getOrThrow()
        apply("call_screening_enabled", policy.callScreeningEnabled).getOrThrow()
        apply("call_allowlist", policy.callAllowlist).getOrThrow()
        apply("contacts_only_calls", policy.contactsOnlyCalls).getOrThrow()
        apply("network_default_mode", policy.defaultNetworkMode).getOrThrow()
        val preferences = context.getSharedPreferences("policy", Context.MODE_PRIVATE)
        val previous = preferences.getStringSet("suspended_packages", emptySet()).orEmpty()
        val removed = previous - policy.suspendedPackages.toSet()
        if (removed.isNotEmpty()) suspendPackages(removed.toList(), false)
        if (policy.suspendedPackages.isNotEmpty()) suspendPackages(policy.suspendedPackages, true)
        preferences.edit().putStringSet("suspended_packages", policy.suspendedPackages.toSet()).apply()
    }

    private fun configureAlwaysOnVpn(enabled: Boolean, lockdown: Boolean) {
        policy.edit()
            .putBoolean(ALWAYS_ON_VPN, enabled)
            .putBoolean(VPN_LOCKDOWN, lockdown)
            .apply()
        if (enabled) {
            dpm.setAlwaysOnVpnPackage(admin, context.packageName, lockdown)
            DefenderVpnService.start(context)
        } else {
            dpm.setAlwaysOnVpnPackage(admin, null, false)
            DefenderVpnService.stop(context)
        }
    }

    private fun rejectSelf(packageName: String) {
        require(packageName.isNotBlank()) { "缺少应用包名" }
        require(packageName != context.packageName) { "不能对 3Pon Defender 执行此操作" }
    }

    private fun setRestriction(restriction: String, enabled: Boolean) {
        if (enabled) dpm.addUserRestriction(admin, restriction) else dpm.clearUserRestriction(admin, restriction)
    }

    @Suppress("DEPRECATION")
    private fun setPasswordMinimumLength(rawLength: Int) {
        val length = rawLength.coerceIn(0, MAX_PASSWORD_LENGTH)
        // Android R+ rejects a length rule until this admin requests a
        // password quality that supports minimum-length constraints.
        dpm.setPasswordQuality(admin, DevicePolicyManager.PASSWORD_QUALITY_NUMERIC)
        dpm.setPasswordMinimumLength(admin, length)
        if (length == 0) {
            dpm.setPasswordQuality(admin, DevicePolicyManager.PASSWORD_QUALITY_UNSPECIFIED)
        }
    }

    private fun capability(key: String, supported: Boolean, reason: String? = null) = DeviceCapability(key, supported, if (supported) null else reason ?: "设备尚未完成 Device Owner 注册")

    private companion object {
        const val POLICY_PREFS = "policy"
        const val NETWORK_BLOCKED_PACKAGES = "network_blocked_packages"
        const val NETWORK_DEFAULT_MODE = "network_default_mode"
        const val SUSPEND_UNAPPROVED_APPS = "suspend_unapproved_apps"
        const val BACKGROUND_PROTECTION = "defender_background_protection"
        const val FORCE_AUDIBLE_RINGER = "force_audible_ringer"
        const val FORCE_AUDIBLE_RINGER_PERIODS = "force_audible_ringer_periods"
        const val FORCE_AUDIBLE_RINGER_ACTIVE = "force_audible_ringer_active"
        const val PREVIOUS_RINGER_MODE = "previous_ringer_mode"
        const val PREVIOUS_RING_VOLUME = "previous_ring_volume"
        const val ALWAYS_ON_VPN = "always_on_vpn"
        const val VPN_LOCKDOWN = "vpn_lockdown"
        const val TEMP_INSTALL_RESTORE_PENDING = "temporary_install_restore_pending"
        const val TEMP_RESTORE_INSTALL = "temporary_restore_install"
        const val TEMP_RESTORE_UNKNOWN_SOURCES = "temporary_restore_unknown_sources"
        const val NETWORK_ALLOW_ALL = "allow_all"
        const val NETWORK_DENY_UNLISTED = "deny_unlisted"
        const val PERMISSION_ALLOW = "granted"
        const val PERMISSION_DENY = "denied"
        const val PERMISSION_DEFAULT = "default"
        const val BRIGHTNESS_AUTOMATIC = "automatic"
        const val BRIGHTNESS_MANUAL = "manual"
        const val WIFI_CONFIG_LOCKDOWN_SETTING = "wifi_device_owner_configs_lockdown"
        const val MIN_BRIGHTNESS = 1
        const val MAX_BRIGHTNESS = 255
        const val MIN_SCREEN_TIMEOUT_MS = 15_000L
        const val MAX_SCREEN_TIMEOUT_MS = 30L * 60L * 1000L
        const val MAX_TIME_TO_LOCK_MS = 30L * 24L * 60L * 60L * 1000L
        const val MAX_LOCK_SCREEN_INFO_LENGTH = 200
        const val MAX_PASSWORD_LENGTH = 16
        const val MAX_RINGER_PERIODS = 16
        val RINGER_PERIOD_PATTERN = Regex("([01]\\d|2[0-3]):([0-5]\\d)-([01]\\d|2[0-3]):([0-5]\\d)")
    }
}

data class PackageSuspensionResult(
    val succeeded: Set<String>,
    val failed: Map<String, String>,
)
