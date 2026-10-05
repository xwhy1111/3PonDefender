package com.threepon.defender

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.app.role.RoleManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.database.ContentObserver
import android.media.AudioManager
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.provider.Settings
import android.util.Log
import android.content.pm.ServiceInfo
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

class DefenderPollingService : Service() {
    private val serviceJob = SupervisorJob()
    private val scope = CoroutineScope(Dispatchers.IO + serviceJob)
    private val http = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()
    private val updateMutex = Mutex()
    private var updateJob: Job? = null
    private var soundMonitoringRegistered = false
    private val soundSettingsObserver = object : ContentObserver(Handler(Looper.getMainLooper())) {
        override fun onChange(selfChange: Boolean) = enforceAudibleRinger()
    }
    private val ringerModeReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) = enforceAudibleRinger()
    }

    override fun onCreate() {
        super.onCreate()
        if (PairingStore(applicationContext).read() == null) {
            stopSelf()
            return
        }
        createNotificationChannel()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, notification("正在连接管控端"), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification("正在连接管控端"))
        }
        runCatching { DefenderVpnService.refresh(applicationContext) }
            .onFailure { Log.w(TAG, "恢复应用联网限制失败", it) }
        registerSoundEnforcement()
        enforceAudibleRinger()
        scope.launch { pollLoop() }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (PairingStore(applicationContext).read() == null) {
            stopSelf()
            return START_NOT_STICKY
        }
        return START_STICKY
    }

    private suspend fun pollLoop() {
        while (scope.isActive) {
            val config = PairingStore(applicationContext).read()
            if (config != null) {
                runCatching { pollOnce(config) }
                    .onSuccess {
                        markServerOnline(true)
                        updateNotification("服务器轮询正常 · ${java.time.LocalTime.now().toString().take(5)}")
                    }
                    .onFailure { error ->
                        markServerOnline(false)
                        if (error !is CancellationException) {
                            Log.w(TAG, "服务器轮询失败", error)
                            updateNotification("服务器暂时无法连接")
                        }
                    }
            }
            delay(POLL_INTERVAL_MS)
        }
    }

    private suspend fun pollOnce(config: PairingConfig) = withContext(Dispatchers.IO) {
        val url = "${config.baseUrl.trimEnd('/')}/api/v1/device/poll?device_id=${config.deviceId}"
        val request = Request.Builder().url(url).header("X-Device-Token", config.deviceToken).get().build()
        http.newCall(request).execute().use { response ->
            val body = response.body?.string().orEmpty()
            check(response.isSuccessful) { "轮询失败: HTTP ${response.code}" }
            val root = JSONObject(body)
            val policyVersion = root.optLong("policy_version", 0)
            val policyPreferences = getSharedPreferences(POLICY_PREFS, MODE_PRIVATE)
            val lastAppliedVersion = policyPreferences.getLong(LAST_POLICY_VERSION, 0)
            val basicPolicy = root.optJSONObject("basic_policy")
            val contactsOnly = basicPolicy?.optBoolean("contacts_only_calls", false) == true
            val callScreeningEnabled = basicPolicy?.optBoolean("call_screening_enabled", false) == true
            policyPreferences.edit()
                .putBoolean("contacts_only_calls_enabled", contactsOnly)
                .putBoolean("call_screening_required", callScreeningEnabled || contactsOnly)
                .apply()
            val policyChanged = policyVersion > 0 && policyVersion != lastAppliedVersion
            if (policyChanged) {
                val failureDetails = linkedMapOf<String, String>()
                val failedSettings = applyPolicy(root.optJSONArray("settings"), failureDetails)
                val failedBasic = applyBasicPolicy(basicPolicy, failureDetails)
                acknowledgePolicy(config, policyVersion, failedSettings + failedBasic, failureDetails)
                if (failedSettings.isEmpty() && failedBasic.isEmpty()) {
                    policyPreferences.edit().putLong(LAST_POLICY_VERSION, policyVersion).apply()
                }
            } else {
                // Reconcile the two Android install restrictions even when the server
                // policy version predates this client fix.
                reconcileInstallationRestrictions(basicPolicy)
            }
            reconcileContactsPermission(basicPolicy)
            runCatching { reportRuntimeStatus(config) }
                .onFailure { Log.w(TAG, "上报来电筛选状态失败", it) }
            // The observer normally restores the call stream immediately. This
            // polling reconciliation is a HyperOS-safe fallback after process or
            // system audio-service restarts.
            enforceAudibleRinger()
            runCatching { syncAppInventory(config) }
                .onFailure { Log.w(TAG, "上传应用清单失败", it) }
            val commands = root.optJSONArray("commands")
            if (commands != null) {
                for (index in 0 until commands.length()) {
                    val command = commands.optJSONObject(index) ?: continue
                    executeCommand(config, command)
                }
            }
            if (!root.isNull("update")) {
                root.optJSONObject("update")?.let { update ->
                    val version = update.optLong("version_code", 0)
                    if (version > BuildConfig.VERSION_CODE) startImmediateUpdate(config, version)
                }
            }
        }
    }

    private fun startImmediateUpdate(config: PairingConfig, versionCode: Long) {
        if (updateJob?.isActive == true) return
        val preferences = getSharedPreferences(UPDATE_PREFS, MODE_PRIVATE)
        val now = System.currentTimeMillis()
        val installingVersion = preferences.getLong(INSTALLING_VERSION_CODE, 0L)
        val installingAt = preferences.getLong(INSTALLING_STARTED_AT, 0L)
        if (installingVersion >= versionCode && now - installingAt < INSTALLATION_TIMEOUT_MS) return
        if (installingVersion > 0L && now - installingAt >= INSTALLATION_TIMEOUT_MS) {
            preferences.edit()
                .remove(INSTALLING_VERSION_CODE)
                .remove(INSTALLING_STARTED_AT)
                .apply()
        }
        val failedVersion = preferences.getLong(LAST_FAILED_VERSION, 0L)
        val failedAt = preferences.getLong(LAST_FAILED_AT, 0L)
        if (failedVersion == versionCode && now - failedAt < UPDATE_RETRY_DELAY_MS) return
        updateJob = scope.launch {
            updateMutex.withLock {
                runCatching { DefenderUpdateManager(applicationContext).checkAndInstall(config) }
                    .onSuccess {
                        preferences.edit().remove(LAST_FAILED_VERSION).remove(LAST_FAILED_AT).apply()
                        updateNotification("已下载更新 v$versionCode，正在由系统安装")
                    }
                    .onFailure { error ->
                        preferences.edit()
                            .putLong(LAST_FAILED_VERSION, versionCode)
                            .putLong(LAST_FAILED_AT, System.currentTimeMillis())
                            .apply()
                        Log.w(TAG, "前台自动更新失败，WorkManager 将继续兜底", error)
                        DefenderUpdateScheduler.checkNow(applicationContext)
                    }
            }
        }
    }

    private fun acknowledgePolicy(
        config: PairingConfig,
        policyVersion: Long,
        failedSettings: List<String>,
        failureDetails: Map<String, String>,
    ) {
        if (policyVersion <= 0) return
        val ack = JSONObject().apply {
            put("device_id", config.deviceId)
            put("status", if (failedSettings.isEmpty()) "applied" else "failed")
            put("policy_version", policyVersion)
            put("failed_settings", org.json.JSONArray(failedSettings))
            put("failure_details", JSONObject(failureDetails))
        }
        val request = Request.Builder()
            .url("${config.baseUrl.trimEnd('/')}/api/v1/device/command-ack")
            .header("X-Device-Token", config.deviceToken)
            .post(ack.toString().toRequestBody(JSON))
            .build()
        runCatching { http.newCall(request).execute().close() }
    }

    private fun applyPolicy(settings: org.json.JSONArray?, failureDetails: MutableMap<String, String>): List<String> {
        if (settings == null) return emptyList()
        val controller = DeviceOwnerController(applicationContext)
        val failed = mutableListOf<String>()
        for (index in 0 until settings.length()) {
            val item = settings.optJSONObject(index) ?: continue
            if (!item.optBoolean("supported", false)) continue
            val value = item.opt("value") ?: continue
            val normalized: Any = if (value is org.json.JSONArray) {
                (0 until value.length()).map { value.optString(it) }
            } else value
            val key = item.optString("key")
            runCatching { controller.apply(key, normalized).getOrThrow() }
                .onFailure { error ->
                    failed += key
                    failureDetails[key] = error.message?.take(300) ?: error.javaClass.simpleName
                    Log.w(TAG, "策略应用失败: $key", error)
                }
        }
        return failed
    }

    private fun applyBasicPolicy(policy: JSONObject?, failureDetails: MutableMap<String, String>): List<String> {
        if (policy == null) return emptyList()
        val failed = mutableListOf<String>()
        failed += reconcileInstallationRestrictions(policy, failureDetails)
        val controller = DeviceOwnerController(applicationContext)
        val booleanSettings = listOf(
            "defender_self_protection" to "defender_uninstall_blocked",
            "call_screening_enabled" to "call_screening_enabled",
            "contacts_only_calls" to "contacts_only_calls",
            "background_protection_enabled" to "defender_background_protection",
        )
        booleanSettings.forEach { (source, target) ->
            if (policy.has(source)) {
                runCatching { controller.apply(target, policy.optBoolean(source)).getOrThrow() }
                    .onFailure {
                        failed += target
                        failureDetails[target] = it.message?.take(300) ?: it.javaClass.simpleName
                        Log.w(TAG, "基础策略应用失败: $target", it)
                    }
            }
        }
        if (policy.has("default_network_mode")) {
            runCatching { controller.apply("network_default_mode", policy.optString("default_network_mode")).getOrThrow() }
                .onFailure {
                    failed += "network_default_mode"
                    failureDetails["network_default_mode"] = it.message?.take(300) ?: it.javaClass.simpleName
                    Log.w(TAG, "基础策略应用失败: network_default_mode", it)
                }
        }
        if (policy.has("call_allowlist")) {
            val numbers = policy.optJSONArray("call_allowlist")?.let { array ->
                (0 until array.length()).map { array.optString(it) }.filter { it.isNotBlank() }
            }.orEmpty()
            runCatching { controller.apply("call_allowlist", numbers).getOrThrow() }
                .onFailure {
                    failed += "call_allowlist"
                    failureDetails["call_allowlist"] = it.message?.take(300) ?: it.javaClass.simpleName
                    Log.w(TAG, "基础策略应用失败: call_allowlist", it)
                }
        }
        val packages = policy.optJSONArray("suspended_packages")
        if (packages != null) {
            val desired = (0 until packages.length()).map { packages.optString(it).trim() }.filter { it.isNotBlank() }.toSet()
            val preferences = getSharedPreferences(POLICY_PREFS, MODE_PRIVATE)
            val previous = preferences.getStringSet(SUSPENDED_PACKAGES, emptySet()).orEmpty()
            val resumed = runCatching { controller.suspendPackagesBestEffort(previous - desired, false) }
            val newlySuspended = runCatching { controller.suspendPackagesBestEffort(desired - previous, true) }
            val operationError = resumed.exceptionOrNull() ?: newlySuspended.exceptionOrNull()
            if (operationError != null) {
                failed += "suspended_packages"
                failureDetails["suspended_packages"] = operationError.message?.take(300) ?: operationError.javaClass.simpleName
                Log.w(TAG, "应用禁用应用列表失败", operationError)
            } else {
                val resumeResult = resumed.getOrThrow()
                val suspendResult = newlySuspended.getOrThrow()
                val active = previous.toMutableSet().apply {
                    removeAll(resumeResult.succeeded)
                    addAll(suspendResult.succeeded)
                }
                preferences.edit().putStringSet(SUSPENDED_PACKAGES, active).apply()
                val packageFailures = resumeResult.failed + suspendResult.failed
                if (packageFailures.isNotEmpty()) {
                    failed += "suspended_packages"
                    failureDetails["suspended_packages"] = packageFailures.entries.joinToString(separator = "; ") { (packageName, reason) ->
                        "$packageName: $reason"
                    }.take(300)
                    Log.w(TAG, "部分应用无法暂停: ${failureDetails["suspended_packages"]}")
                }
            }
        }
        return failed.distinct()
    }

    private fun reconcileInstallationRestrictions(
        policy: JSONObject?,
        failureDetails: MutableMap<String, String> = linkedMapOf(),
    ): List<String> {
        if (policy == null || !policy.has("installation_approval_required")) return emptyList()
        val value = policy.optBoolean("installation_approval_required")
        val controller = DeviceOwnerController(applicationContext)
        val failed = mutableListOf<String>()
        listOf("block_user_install", "block_unknown_sources").forEach { key ->
            runCatching { controller.apply(key, value).getOrThrow() }
                .onFailure {
                    failed += key
                    failureDetails[key] = it.message?.take(300) ?: it.javaClass.simpleName
                    Log.w(TAG, "安装限制应用失败: $key", it)
                }
        }
        return failed
    }

    private fun executeCommand(config: PairingConfig, command: JSONObject) {
        val controller = DeviceOwnerController(applicationContext)
        val kind = command.optString("kind")
        var deferredAck = false
        val result = runCatching {
            when (kind) {
                "block_user_install" -> controller.apply("block_user_install", true).getOrThrow()
                "release_self_protection" -> controller.apply("defender_uninstall_blocked", false).getOrThrow()
                "suspend_app" -> controller.suspendPackage(commandPackage(command), command.optJSONObject("payload")?.optBoolean("suspended", true) ?: true)
                "hide_app" -> controller.hidePackage(commandPackage(command), command.optJSONObject("payload")?.optBoolean("hidden", true) ?: true)
                "uninstall_app" -> {
                    controller.uninstallPackage(commandPackage(command), command.optString("id"))
                    deferredAck = true
                }
                "network_block" -> controller.setNetworkBlocked(commandPackage(command), true)
                "network_allow" -> controller.setNetworkBlocked(commandPackage(command), false)
                "set_app_permission" -> {
                    val payload = command.optJSONObject("payload") ?: error("缺少应用权限参数")
                    val permission = payload.optString("permission")
                    val grantState = payload.optString("grant_state")
                    require(permission.isNotBlank() && grantState.isNotBlank()) { "应用权限参数不完整" }
                    controller.setPermissionGrantState(commandPackage(command), permission, grantState)
                }
                "set_system_setting" -> {
                    val payload = command.optJSONObject("payload") ?: error("缺少系统设置参数")
                    val key = payload.optString("key")
                    require(key.isNotBlank()) { "缺少系统设置键" }
                    val value = payload.opt("value")
                    require(value != null && value !== JSONObject.NULL) { "系统设置缺少值" }
                    controller.apply(key, value).getOrThrow()
                }
                else -> Unit
            }
        }
        if (deferredAck && result.isSuccess) return
        val ack = JSONObject().apply {
            put("device_id", config.deviceId)
            put("command_id", command.optString("id"))
            put("status", if (result.isSuccess) "applied" else "failed")
            result.exceptionOrNull()?.message?.let { put("message", it) }
        }
        val request = Request.Builder()
            .url("${config.baseUrl.trimEnd('/')}/api/v1/device/command-ack")
            .header("X-Device-Token", config.deviceToken)
            .post(ack.toString().toRequestBody(JSON))
            .build()
        runCatching { http.newCall(request).execute().close() }
    }

    private fun commandPackage(command: JSONObject): String =
        command.optJSONObject("payload")?.optString("package_name").orEmpty()

    private fun syncAppInventory(config: PairingConfig) {
        val snapshot = AppInventory.collect(applicationContext)
        val preferences = getSharedPreferences(INVENTORY_PREFS, MODE_PRIVATE)
        val previousRevision = preferences.getString(LAST_INVENTORY_REVISION, null)
        val lastSentAt = preferences.getLong(LAST_INVENTORY_SENT_AT, 0L)
        val currentTime = System.currentTimeMillis()
        if (snapshot.revision == previousRevision && currentTime - lastSentAt < INVENTORY_HEARTBEAT_MS) return
        val body = JSONObject().apply {
            put("device_id", config.deviceId)
            put("revision", snapshot.revision)
            put("apps", snapshot.apps)
        }
        val request = Request.Builder()
            .url("${config.baseUrl.trimEnd('/')}/api/v1/device/apps")
            .header("X-Device-Token", config.deviceToken)
            .post(body.toString().toRequestBody(JSON))
            .build()
        http.newCall(request).execute().use { response ->
            check(response.isSuccessful) { "应用清单上传失败: HTTP ${response.code}" }
        }
        preferences.edit()
            .putString(LAST_INVENTORY_REVISION, snapshot.revision)
            .putLong(LAST_INVENTORY_SENT_AT, currentTime)
            .apply()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            getSystemService(NotificationManager::class.java).createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "3Pon Defender 管控连接", NotificationManager.IMPORTANCE_LOW),
            )
        }
    }

    private fun notification(text: String): Notification = NotificationCompat.Builder(this, CHANNEL_ID)
        .setSmallIcon(android.R.drawable.stat_sys_warning)
        .setContentTitle("3Pon Defender")
        .setContentText(text)
        .setOngoing(true)
        .setContentIntent(PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT))
        .build()

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification(text))
    }

    private fun markServerOnline(online: Boolean) {
        getSharedPreferences(POLICY_PREFS, MODE_PRIVATE).edit()
            .putBoolean("server_online", online)
            .putLong("server_last_poll_at", if (online) System.currentTimeMillis() else 0L)
            .apply()
    }

    private fun reconcileContactsPermission(basicPolicy: JSONObject?) {
        val enabled = basicPolicy?.optBoolean("contacts_only_calls", false) == true
        if (!enabled || checkSelfPermission(Manifest.permission.READ_CONTACTS) == PackageManager.PERMISSION_GRANTED) return
        val preferences = getSharedPreferences(POLICY_PREFS, MODE_PRIVATE)
        val lastAttempt = preferences.getLong("contacts_permission_last_attempt", 0L)
        if (System.currentTimeMillis() - lastAttempt < CONTACT_PERMISSION_RETRY_MS) return
        preferences.edit().putLong("contacts_permission_last_attempt", System.currentTimeMillis()).apply()
        runCatching { DeviceOwnerController(applicationContext).apply("contacts_only_calls", true).getOrThrow() }
            .onSuccess {
                preferences.edit().remove("contacts_permission_last_attempt").apply()
                Log.i(TAG, "已为通讯录来电筛选自动授予 READ_CONTACTS")
            }
            .onFailure { Log.w(TAG, "自动授予通讯录读取权限失败", it) }
    }

    private fun reportRuntimeStatus(config: PairingConfig) {
        val roleManager = getSystemService(RoleManager::class.java)
        val preferences = getSharedPreferences(POLICY_PREFS, MODE_PRIVATE)
        val lastScreenedAt = preferences.getLong("last_screened_call_at_epoch_ms", 0L)
        val body = JSONObject().apply {
            put("device_id", config.deviceId)
            put("device_owner_active", DeviceOwnerController(applicationContext).isDeviceOwner())
            put("call_screening_role_available", roleManager?.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING) == true)
            put("call_screening_role_held", roleManager?.isRoleHeld(RoleManager.ROLE_CALL_SCREENING) == true)
            put("contacts_permission_granted", checkSelfPermission(Manifest.permission.READ_CONTACTS) == PackageManager.PERMISSION_GRANTED)
            put("call_screening_enabled", preferences.getBoolean("call_screening_enabled", true))
            put("contacts_only_calls", preferences.getBoolean("contacts_only_calls", false))
            put("last_screened_call_at", if (lastScreenedAt > 0L) java.time.Instant.ofEpochMilli(lastScreenedAt).toString() else JSONObject.NULL)
            put("screened_call_count", preferences.getInt("screened_incoming_call_count", 0))
            put("blocked_call_count", preferences.getInt("blocked_incoming_call_count", 0))
        }
        val request = Request.Builder()
            .url("${config.baseUrl.trimEnd('/')}/api/v1/device/runtime-status")
            .header("X-Device-Token", config.deviceToken)
            .post(body.toString().toRequestBody(JSON))
            .build()
        http.newCall(request).execute().use { response ->
            check(response.isSuccessful) { "来电筛选状态上报失败: HTTP ${response.code}" }
        }
    }

    private fun registerSoundEnforcement() {
        if (soundMonitoringRegistered) return
        contentResolver.registerContentObserver(Settings.System.CONTENT_URI, true, soundSettingsObserver)
        val filter = IntentFilter(AudioManager.RINGER_MODE_CHANGED_ACTION)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(ringerModeReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(ringerModeReceiver, filter)
        }
        soundMonitoringRegistered = true
    }

    private fun enforceAudibleRinger() {
        runCatching { DeviceOwnerController(applicationContext).enforceAudibleRinger() }
            .onFailure { Log.w(TAG, "恢复强制响铃失败", it) }
    }

    override fun onDestroy() {
        if (soundMonitoringRegistered) {
            runCatching { contentResolver.unregisterContentObserver(soundSettingsObserver) }
            runCatching { unregisterReceiver(ringerModeReceiver) }
            soundMonitoringRegistered = false
        }
        updateJob?.cancel()
        serviceJob.cancel()
        http.dispatcher.executorService.shutdown()
        http.connectionPool.evictAll()
        super.onDestroy()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        // START_STICKY is normally enough. This extra restart request helps on
        // HyperOS builds that remove a task while leaving its service stopped.
        val keepAlive = getSharedPreferences(POLICY_PREFS, MODE_PRIVATE)
            .getBoolean(BACKGROUND_PROTECTION, true)
        if (keepAlive) runCatching { start(applicationContext) }
        super.onTaskRemoved(rootIntent)
    }

    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        private const val TAG = "3PonDefenderPoll"
        private const val CHANNEL_ID = "threepon_polling"
        private const val NOTIFICATION_ID = 3015
        private const val POLL_INTERVAL_MS = 10_000L
        private const val CONTACT_PERMISSION_RETRY_MS = 60_000L
        private const val UPDATE_RETRY_DELAY_MS = 60_000L
        private const val POLICY_PREFS = "policy"
        private const val BACKGROUND_PROTECTION = "defender_background_protection"
        private const val LAST_POLICY_VERSION = "last_applied_policy_version"
        private const val SUSPENDED_PACKAGES = "suspended_packages"
        private const val UPDATE_PREFS = "threepon_update"
        private const val LAST_FAILED_VERSION = "last_failed_version"
        private const val LAST_FAILED_AT = "last_failed_at"
        private const val INSTALLING_VERSION_CODE = "installing_version_code"
        private const val INSTALLING_STARTED_AT = "installing_started_at"
        private const val INSTALLATION_TIMEOUT_MS = 15L * 60L * 1000L
        private const val INVENTORY_PREFS = "threepon_inventory"
        private const val LAST_INVENTORY_REVISION = "last_inventory_revision"
        private const val LAST_INVENTORY_SENT_AT = "last_inventory_sent_at"
        private const val INVENTORY_HEARTBEAT_MS = POLL_INTERVAL_MS
        private val JSON = "application/json".toMediaType()

        fun start(context: Context) {
            if (PairingStore(context.applicationContext).read() == null) return
            val intent = Intent(context, DefenderPollingService::class.java)
            if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(intent) else context.startService(intent)
        }
    }
}
