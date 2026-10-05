package com.threepon.defender

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.util.Base64
import android.util.Log
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

data class UpdateManifest(
    val packageName: String,
    val versionCode: Long,
    val versionName: String,
    val apkUrl: String,
    val sha256: String,
    val signerSha256: String,
    val manifestSignature: String,
    val signedPayload: String,
    val mandatory: Boolean,
) {
    companion object {
        fun fromJson(raw: String): UpdateManifest {
            val json = JSONObject(raw)
            return UpdateManifest(
                packageName = json.getString("package_name"),
                versionCode = json.getLong("version_code"),
                versionName = json.getString("version_name"),
                apkUrl = json.getString("apk_url"),
                sha256 = json.getString("sha256").lowercase(),
                signerSha256 = json.getString("signer_sha256").lowercase(),
                manifestSignature = json.getString("manifest_signature"),
                signedPayload = json.getString("signed_payload"),
                mandatory = json.optBoolean("mandatory", false),
            )
        }
    }
}

object DefenderUpdateScheduler {
    private const val PERIODIC_WORK = "threepon.update.periodic"
    private const val IMMEDIATE_WORK = "threepon.update.immediate"

    fun schedule(context: Context) {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()
        // This is only a recovery path. The foreground polling service checks
        // the manifest directly every 10 seconds.
        val request = PeriodicWorkRequestBuilder<DefenderUpdateWorker>(6, TimeUnit.HOURS)
            .setConstraints(constraints)
            .build()
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(PERIODIC_WORK, ExistingPeriodicWorkPolicy.UPDATE, request)
    }

    fun checkNow(context: Context) {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()
        val request = OneTimeWorkRequestBuilder<DefenderUpdateWorker>()
            .setConstraints(constraints)
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(IMMEDIATE_WORK, ExistingWorkPolicy.REPLACE, request)
    }
}

/** Best-effort status reporting. The device never treats a failed status post as an update failure. */
object DefenderUpdateStatusReporter {
    private val http = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(8, TimeUnit.SECONDS)
        .build()
    private val jsonType = "application/json".toMediaType()

    fun report(context: Context, config: PairingConfig, status: String, versionCode: Long, message: String? = null) {
        val body = JSONObject().apply {
            put("device_id", config.deviceId)
            put("status", status)
            put("version_code", versionCode)
            message?.takeIf { it.isNotBlank() }?.let { put("message", it.take(500)) }
        }
        val request = Request.Builder()
            .url("${config.baseUrl.trimEnd('/')}/api/v1/device/update-status")
            .header("X-Device-Token", config.deviceToken)
            .post(body.toString().toRequestBody(jsonType))
            .build()
        runCatching { http.newCall(request).execute().use { } }
            .onFailure { Log.d(TAG, "更新状态回报失败", it) }
    }

    private const val TAG = "3PonDefenderUpdate"
}

/** Performs the update in the foreground service as soon as a new manifest is seen. */
class DefenderUpdateManager(private val context: Context) {
    private val http = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(90, TimeUnit.SECONDS)
        .build()

    fun checkAndInstall(config: PairingConfig) = synchronized(INSTALL_LOCK) {
        checkAndInstallLocked(config)
    }

    private fun checkAndInstallLocked(config: PairingConfig) {
        check(DeviceOwnerController(context).isDeviceOwner()) { "自动更新需要 Device Owner 权限" }
        var targetVersion = 0L
        try {
            DefenderUpdateStatusReporter.report(context, config, "checking", 0)
            val manifestUrl = Uri.parse(config.updateManifestUrl).buildUpon()
                .appendQueryParameter("device_id", config.deviceId)
                .build()
                .toString()
            require(sameOrigin(config.baseUrl, config.updateManifestUrl)) { "更新清单地址不是配对服务器" }
            val manifestRequest = Request.Builder()
                .url(manifestUrl)
                .header("X-Device-Token", config.deviceToken)
                .header("Cache-Control", "no-cache")
                .build()
            val manifest = http.newCall(manifestRequest).execute().use { response ->
                val body = response.body?.string().orEmpty()
                require(response.isSuccessful) { "更新清单请求失败: ${response.code}" }
                UpdateManifest.fromJson(body)
            }
            targetVersion = manifest.versionCode
            if (manifest.versionCode <= BuildConfig.VERSION_CODE) {
                DefenderUpdateStatusReporter.report(context, config, "idle", manifest.versionCode)
                return
            }
            val updatePreferences = context.getSharedPreferences("threepon_update", Context.MODE_PRIVATE)
            val installingVersion = updatePreferences.getLong("installing_version_code", 0L)
            val installingAt = updatePreferences.getLong("installing_started_at", 0L)
            if (installingVersion >= manifest.versionCode && System.currentTimeMillis() - installingAt < INSTALLATION_TIMEOUT_MS) {
                DefenderUpdateStatusReporter.report(context, config, "installing", manifest.versionCode)
                return
            }
            if (installingVersion > 0L) {
                updatePreferences.edit()
                    .remove("installing_version_code")
                    .remove("installing_started_at")
                    .apply()
            }
            validateManifest(config, manifest)

            val updatesDir = File(context.cacheDir, "updates").apply { mkdirs() }
            val apkFile = File(updatesDir, "threepon-defender-${manifest.versionCode}.apk")
            val partialFile = File(updatesDir, "threepon-defender-${manifest.versionCode}.apk.part")
            DefenderUpdateStatusReporter.report(context, config, "downloading", manifest.versionCode)
            download(manifest, config, partialFile)
            if (apkFile.exists()) apkFile.delete()
            check(partialFile.renameTo(apkFile)) { "无法保存更新包" }
            DefenderUpdateStatusReporter.report(context, config, "verifying", manifest.versionCode)
            verifyApk(apkFile, manifest)
            DefenderUpdateStatusReporter.report(context, config, "installing", manifest.versionCode)
            val preferences = context.getSharedPreferences("threepon_update", Context.MODE_PRIVATE)
            preferences.edit()
                .putLong("installing_version_code", manifest.versionCode)
                .putLong("installing_started_at", System.currentTimeMillis())
                .apply()
            var installSubmitted = false
            try {
                install(apkFile)
                installSubmitted = true
            } finally {
                if (!installSubmitted) {
                    preferences.edit()
                        .remove("installing_version_code")
                        .remove("installing_started_at")
                        .apply()
                }
            }
        } catch (error: Throwable) {
            DefenderUpdateStatusReporter.report(context, config, "failed", targetVersion, error.message)
            throw error
        }
    }

    private fun validateManifest(config: PairingConfig, manifest: UpdateManifest) {
        require(manifest.packageName == context.packageName) { "更新包名不匹配" }
        require(manifest.versionCode > BuildConfig.VERSION_CODE) { "没有更高版本" }
        require(manifest.sha256.matches(Regex("[0-9a-f]{64}"))) { "更新清单缺少 APK SHA-256" }
        require(manifest.signerSha256.matches(Regex("[0-9a-f]{64}"))) { "更新清单缺少签名证书摘要" }
        require(sameOrigin(config.baseUrl, manifest.apkUrl)) { "更新包地址不是配对服务器" }

        val payload = Base64.decode(manifest.signedPayload, Base64.DEFAULT)
        val signature = Base64.decode(manifest.manifestSignature, Base64.DEFAULT)
        val rawPublicKey = Base64.decode(config.serverPublicKey, Base64.DEFAULT)
        require(rawPublicKey.size == 32) { "服务器公钥长度无效" }
        val verifier = Ed25519Signer().apply {
            init(false, Ed25519PublicKeyParameters(rawPublicKey, 0))
            update(payload, 0, payload.size)
        }
        require(verifier.verifySignature(signature)) { "更新清单签名无效" }
        val signed = JSONObject(String(payload, Charsets.UTF_8))
        require(signed.getString("package_name") == manifest.packageName) { "更新清单包名被篡改" }
        require(signed.getLong("version_code") == manifest.versionCode) { "更新清单版本被篡改" }
        require(signed.getString("version_name") == manifest.versionName) { "更新清单版本名称被篡改" }
        require(signed.getString("apk_url") == manifest.apkUrl) { "更新清单下载地址被篡改" }
        require(signed.getString("sha256").lowercase() == manifest.sha256) { "更新清单哈希被篡改" }
        require(signed.getString("signer_sha256").lowercase() == manifest.signerSha256) { "更新清单证书摘要被篡改" }
        require(signed.optBoolean("mandatory", false) == manifest.mandatory) { "更新清单强制标记被篡改" }
    }

    private fun download(manifest: UpdateManifest, config: PairingConfig, destination: File) {
        if (destination.exists()) destination.delete()
        val request = Request.Builder()
            .url(manifest.apkUrl)
            .header("X-Device-Token", config.deviceToken)
            .header("Cache-Control", "no-cache")
            .build()
        http.newCall(request).execute().use { response ->
            require(response.isSuccessful) { "更新包下载失败: ${response.code}" }
            val body = response.body ?: error("更新包为空")
            val digest = MessageDigest.getInstance("SHA-256")
            body.byteStream().use { input ->
                FileOutputStream(destination).use { output ->
                    val buffer = ByteArray(32 * 1024)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        output.write(buffer, 0, count)
                        digest.update(buffer, 0, count)
                    }
                    output.fd.sync()
                }
            }
            require(digest.digest().toHex() == manifest.sha256) { "更新包 SHA-256 校验失败" }
        }
    }

    private fun verifyApk(apk: File, manifest: UpdateManifest) {
        require(apk.length() > 0) { "更新包为空" }
        val packageInfo = context.packageManager.getPackageArchiveInfo(apk.absolutePath, PackageManager.GET_SIGNING_CERTIFICATES)
            ?: error("无法读取更新包签名")
        require(packageInfo.packageName == context.packageName) { "更新包包名不匹配" }
        val signers = if (Build.VERSION.SDK_INT >= 28) packageInfo.signingInfo?.apkContentsSigners.orEmpty() else emptyArray()
        require(signers.isNotEmpty()) { "更新包没有有效签名" }
        val signerDigest = sha256(signers.first().toByteArray())
        require(signerDigest == manifest.signerSha256) { "更新包签名证书不匹配" }
        require(signerDigest == installedSignerSha256()) { "更新包不是当前安装版本的签名证书" }
    }

    private fun installedSignerSha256(): String {
        val packageInfo = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val signers = if (Build.VERSION.SDK_INT >= 28) packageInfo.signingInfo?.apkContentsSigners.orEmpty() else emptyArray()
        require(signers.isNotEmpty()) { "当前应用没有有效签名" }
        return sha256(signers.first().toByteArray())
    }

    private fun install(apk: File) {
        val policyController = DeviceOwnerController(context)
        val installer = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(context.packageName)
            setSize(apk.length())
            if (Build.VERSION.SDK_INT >= 23) setInstallReason(PackageManager.INSTALL_REASON_POLICY)
            if (Build.VERSION.SDK_INT >= 31) {
                setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
                setPackageSource(PackageInstaller.PACKAGE_SOURCE_DOWNLOADED_FILE)
            }
        }
        var sessionId = -1
        try {
            policyController.preparePackageInstall()
            sessionId = installer.createSession(params)
            installer.openSession(sessionId).use { session ->
                apk.inputStream().use { input ->
                    session.openWrite("base.apk", 0, apk.length()).use { output ->
                        input.copyTo(output)
                        session.fsync(output)
                    }
                }
                // Mutable is required here because PackageInstaller fills the
                // result extras into the status PendingIntent on Android 12+.
                val callback = PendingIntent.getBroadcast(
                    context,
                    sessionId,
                    Intent(context, UpdateInstallReceiver::class.java),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
                )
                session.commit(callback.intentSender)
            }
        } catch (error: Throwable) {
            runCatching { policyController.restorePackageInstallRestrictions() }
            if (sessionId >= 0) runCatching { installer.abandonSession(sessionId) }
            throw error
        }
    }

    private fun sameOrigin(base: String, candidate: String): Boolean {
        val expected = Uri.parse(base)
        val actual = Uri.parse(candidate)
        fun port(uri: Uri): Int = if (uri.port != -1) uri.port else if (uri.scheme == "https") 443 else 80
        return expected.scheme == actual.scheme && expected.host == actual.host && port(expected) == port(actual)
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).toHex()

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    companion object {
        private const val TAG = "3PonDefenderUpdate"
        private const val INSTALLATION_TIMEOUT_MS = 15L * 60L * 1000L
        private val INSTALL_LOCK = Any()
    }
}

class DefenderUpdateWorker(
    appContext: Context,
    workerParams: WorkerParameters,
) : CoroutineWorker(appContext, workerParams) {
    override suspend fun doWork(): Result {
        val config = PairingStore(applicationContext).read() ?: return Result.success()
        return runCatching { DefenderUpdateManager(applicationContext).checkAndInstall(config) }
            .fold(
                onSuccess = { Result.success() },
                onFailure = { error ->
                    Log.w("3PonDefenderUpdate", "兜底自动更新失败，当前版本保留", error)
                    if (runAttemptCount < 2) Result.retry() else Result.failure()
                },
            )
    }
}
