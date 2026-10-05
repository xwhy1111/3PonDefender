package com.threepon.defender

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class PairingStore(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences("threepon_pairing", Context.MODE_PRIVATE)
    private val keyAlias = "threepon_pairing_aes_v1"

    fun read(): PairingConfig? = runCatching {
        val encoded = preferences.getString(KEY, null) ?: return null
        val packed = Base64.decode(encoded, Base64.NO_WRAP)
        require(packed.size > GCM_IV_LENGTH) { "配对凭据损坏" }
        val iv = packed.copyOfRange(0, GCM_IV_LENGTH)
        val encrypted = packed.copyOfRange(GCM_IV_LENGTH, packed.size)
        val cipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(GCM_TAG_LENGTH, iv))
        }
        val json = JSONObject(String(cipher.doFinal(encrypted), Charsets.UTF_8))
        PairingConfig(
            baseUrl = json.getString("base_url"),
            deviceId = json.getString("device_id"),
            deviceToken = json.getString("device_token"),
            serverPublicKey = json.getString("server_public_key"),
            updateManifestUrl = json.getString("update_manifest_url"),
            consentVersion = json.getString("consent_version"),
            pairedAtEpochMillis = json.getLong("paired_at"),
        )
    }.getOrNull()

    fun save(config: PairingConfig) {
        val plaintext = JSONObject().apply {
            put("base_url", config.baseUrl)
            put("device_id", config.deviceId)
            put("device_token", config.deviceToken)
            put("server_public_key", config.serverPublicKey)
            put("update_manifest_url", config.updateManifestUrl)
            put("consent_version", config.consentVersion)
            put("paired_at", config.pairedAtEpochMillis)
        }.toString().toByteArray(Charsets.UTF_8)
        val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key()) }
        val encrypted = cipher.doFinal(plaintext)
        val packed = ByteArray(cipher.iv.size + encrypted.size)
        cipher.iv.copyInto(packed, 0)
        encrypted.copyInto(packed, cipher.iv.size)
        preferences.edit().putString(KEY, Base64.encodeToString(packed, Base64.NO_WRAP)).apply()
    }

    fun clear() {
        preferences.edit().remove(KEY).apply()
    }

    private fun key(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getKey(keyAlias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    private companion object {
        const val KEY = "encrypted_pairing_config"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_IV_LENGTH = 12
        const val GCM_TAG_LENGTH = 128
    }
}
