package com.threepon.defender

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit

class PairingClient {
    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .build()

    fun claim(context: android.content.Context, payload: PairingPayload, consented: Boolean): PairingConfig {
        val endpoint = payload.baseUrl.trimEnd('/') + "/api/v1/device/pairing/claim"
        val request = Request.Builder()
            .url(endpoint)
            .post(payload.toClaimJson(context, consented).toString().toRequestBody(JSON))
            .build()
        client.newCall(request).execute().use { response ->
            val body = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw IOException(JSONObject(body).optString("error", "配对请求失败"))
            }
            val result = JSONObject(body)
            require(result.optBoolean("ok")) { result.optString("error", "服务器拒绝配对") }
            val serverPublicKey = result.getString("server_public_key")
            require(serverPublicKey == payload.serverPublicKey) { "服务器公钥与二维码不一致" }
            val baseUrl = result.getString("base_url").trimEnd('/')
            require(baseUrl == payload.baseUrl) { "服务器返回的地址与二维码不一致" }
            val updateManifestUrl = result.optString("update_manifest_url").ifBlank { payload.updateManifestUrl }
            require(updateManifestUrl == payload.updateManifestUrl) { "服务器返回的更新地址与二维码不一致" }
            require(result.optString("device_id").isNotBlank()) { "服务器未返回设备编号" }
            require(result.optString("device_token").isNotBlank()) { "服务器未返回设备凭据" }
            return PairingConfig(
                baseUrl = baseUrl,
                deviceId = result.getString("device_id"),
                deviceToken = result.getString("device_token"),
                serverPublicKey = serverPublicKey,
                updateManifestUrl = updateManifestUrl,
                consentVersion = result.optString("consent_version", CONSENT_VERSION),
                pairedAtEpochMillis = System.currentTimeMillis(),
            )
        }
    }

    private companion object {
        val JSON = "application/json".toMediaType()
    }
}
