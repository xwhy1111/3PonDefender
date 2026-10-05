package com.threepon.defender

import android.net.Uri
import android.os.Build
import android.util.Base64
import org.json.JSONObject
import java.time.Instant

const val CONSENT_VERSION = "2026-09-13-v1"

data class PairingPayload(
    val sessionId: String,
    val pairingToken: String,
    val baseUrl: String,
    val serverPublicKey: String,
    val updateManifestUrl: String,
    val expiresAt: String,
) {
    companion object {
        fun fromJson(raw: String): PairingPayload {
            val json = JSONObject(raw)
            require(json.optString("kind") == "3pon_pairing") { "不是 3Pon Defender 配对二维码" }
            require(json.optInt("version") == 1) { "不支持的配对二维码版本" }
            val sessionId = json.optString("session_id").trim()
            val pairingToken = json.optString("pairing_token").trim()
            val baseUrl = json.optString("base_url").trim().trimEnd('/')
            val serverPublicKey = json.optString("server_public_key").trim()
            val updateManifestUrl = json.optString("update_manifest_url").trim().ifBlank { "$baseUrl/api/v1/device/update-manifest" }
            val expiresAt = json.optString("expires_at").trim()
            require(sessionId.isNotEmpty() && pairingToken.isNotEmpty()) { "配对二维码缺少一次性凭据" }
            require(Base64.decode(serverPublicKey, Base64.DEFAULT).size == 32) { "服务器公钥格式无效" }
            val baseUri = parsePairingOrigin(baseUrl)
            val updateUri = Uri.parse(updateManifestUrl)
            require(pairingSameOrigin(baseUri, updateUri)) { "更新地址必须与管控端同源" }
            require(updateUri.path == "/api/v1/device/update-manifest") { "更新清单地址无效" }
            require(updateUri.query == null && updateUri.fragment == null) { "更新清单地址不能包含查询参数或片段" }
            require(expiresAt.isNotEmpty() && Instant.parse(expiresAt).isAfter(Instant.now())) { "配对二维码已过期" }
            return PairingPayload(sessionId, pairingToken, baseUrl, serverPublicKey, updateManifestUrl, expiresAt)
        }
    }
}

data class PairingConfig(
    val baseUrl: String,
    val deviceId: String,
    val deviceToken: String,
    val serverPublicKey: String,
    val updateManifestUrl: String,
    val consentVersion: String,
    val pairedAtEpochMillis: Long,
)

fun PairingPayload.toClaimJson(context: android.content.Context, consented: Boolean): JSONObject = JSONObject().apply {
    put("session_id", sessionId)
    put("pairing_token", pairingToken)
    put("device_name", "长辈手机 · ${Build.MODEL}")
    put("package_name", context.packageName)
    put("model", Build.MODEL)
    put("manufacturer", Build.MANUFACTURER)
    put("android_api", Build.VERSION.SDK_INT)
    put("hyperos_version", "Android ${Build.VERSION.RELEASE}")
    put("device_owner", DeviceOwnerController(context).isDeviceOwner())
    put("consented", consented)
    put("consent_version", CONSENT_VERSION)
}

private fun parsePairingOrigin(raw: String): Uri {
    val uri = Uri.parse(raw)
    val httpAllowed = BuildConfig.DEBUG && uri.scheme == "http"
    require(uri.scheme == "https" || httpAllowed) { "release 配对必须使用 HTTPS" }
    require(!uri.host.isNullOrBlank()) { "管控端地址缺少主机名" }
    require(uri.encodedAuthority?.contains("@") != true) { "管控端地址不能包含用户信息" }
    require(uri.path.isNullOrEmpty() || uri.path == "/") { "管控端地址必须是 origin，不能包含路径" }
    require(uri.query == null && uri.fragment == null) { "管控端地址不能包含查询参数或片段" }
    return uri
}

private fun pairingSameOrigin(expected: Uri, actual: Uri): Boolean {
    val actualHttpAllowed = BuildConfig.DEBUG && actual.scheme == "http"
    if (actual.scheme != "https" && !actualHttpAllowed) return false
    if (expected.scheme != actual.scheme || expected.host != actual.host) return false
    val expectedPort = if (expected.port == -1) defaultPort(expected.scheme) else expected.port
    val actualPort = if (actual.port == -1) defaultPort(actual.scheme) else actual.port
    return expectedPort == actualPort && actual.encodedAuthority?.contains("@") != true
}

private fun defaultPort(scheme: String?): Int = if (scheme == "https") 443 else 80
