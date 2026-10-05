package com.threepon.defender

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit

class AdminAuthClient {
    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    fun verifyPassword(config: PairingConfig, password: String): Boolean {
        require(password.isNotBlank()) { "请输入管理员密码" }
        val body = JSONObject().put("password", password).toString().toRequestBody(JSON)
        val request = Request.Builder()
            .url("${config.baseUrl.trimEnd('/')}/api/v1/device/admin-verify")
            .header("X-Device-Token", config.deviceToken)
            .post(body)
            .build()
        client.newCall(request).execute().use { response ->
            val result = JSONObject(response.body?.string().orEmpty())
            if (!response.isSuccessful) {
                throw IOException(result.optString("error").ifBlank { result.optString("detail", "管理员密码验证失败") })
            }
            return result.optBoolean("ok", false)
        }
    }

    private companion object {
        val JSON = "application/json".toMediaType()
    }
}
