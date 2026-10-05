package com.threepon.defender

import android.content.Context
import android.util.Log
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Sends the result of an asynchronous device-owner command back to the
 * control service.  PackageInstaller callbacks can arrive after the polling
 * service has returned, so this reporter is intentionally independent of the
 * service coroutine scope.
 */
object DefenderCommandAckReporter {
    private val http = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(8, TimeUnit.SECONDS)
        .build()
    private val jsonType = "application/json".toMediaType()

    fun report(context: Context, config: PairingConfig, commandId: String, status: String, message: String? = null) {
        val body = JSONObject().apply {
            put("device_id", config.deviceId)
            put("command_id", commandId)
            put("status", status)
            message?.takeIf { it.isNotBlank() }?.let { put("message", it.take(500)) }
        }
        val request = Request.Builder()
            .url("${config.baseUrl.trimEnd('/')}/api/v1/device/command-ack")
            .header("X-Device-Token", config.deviceToken)
            .post(body.toString().toRequestBody(jsonType))
            .build()
        runCatching { http.newCall(request).execute().use { response -> check(response.isSuccessful) } }
            .onFailure { Log.w(TAG, "异步命令结果回报失败", it) }
    }

    private const val TAG = "3PonDefenderCommand"
}
