package com.threepon.defender

import android.Manifest
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.ContactsContract
import android.telecom.Call
import android.telecom.CallScreeningService
import android.telephony.PhoneNumberUtils
import android.util.Log

class DefenderCallScreeningService : CallScreeningService() {
    override fun onScreenCall(callDetails: Call.Details) {
        if (callDetails.callDirection == Call.Details.DIRECTION_OUTGOING) {
            respondToCall(callDetails, CallResponse.Builder().build())
            return
        }

        val number = callDetails.handle?.schemeSpecificPart?.trim().orEmpty()
        val policy = getSharedPreferences("policy", MODE_PRIVATE)
        val allowlist = policy
            .getStringSet("call_allowlist", setOf("110", "120", "119"))
            .orEmpty()
        val screeningEnabled = policy.getBoolean("call_screening_enabled", true)
        val contactsOnly = policy.getBoolean("contacts_only_calls", false)
        val filteringActive = screeningEnabled || contactsOnly
        val emergency = isEmergencyNumber(number)
        val allowlisted = allowlist.any { matchesPhoneNumber(number, it) }
        val contact = contactsOnly && !emergency && !allowlisted && isSavedContact(number)
        val allowed = !filteringActive || emergency || allowlisted || contact
        recordIncomingDecision(policy, allowed)
        Log.i(TAG, "来电筛选: active=$filteringActive, contactMode=$contactsOnly, contact=$contact, allowlisted=$allowlisted, allowed=$allowed")
        respondToCall(
            callDetails,
            CallResponse.Builder()
                .setDisallowCall(!allowed)
                .setRejectCall(!allowed)
                .setSkipCallLog(false)
                .setSkipNotification(false)
                .build(),
        )
    }

    private fun recordIncomingDecision(policy: android.content.SharedPreferences, allowed: Boolean) {
        val screened = policy.getInt("screened_incoming_call_count", 0)
        val blocked = policy.getInt("blocked_incoming_call_count", 0)
        policy.edit()
            .putLong("last_screened_call_at_epoch_ms", System.currentTimeMillis())
            .putInt("screened_incoming_call_count", if (screened < Int.MAX_VALUE) screened + 1 else screened)
            .putInt("blocked_incoming_call_count", if (!allowed && blocked < Int.MAX_VALUE) blocked + 1 else blocked)
            .apply()
    }

    private fun isSavedContact(number: String): Boolean {
        if (number.isBlank() || checkSelfPermission(Manifest.permission.READ_CONTACTS) != PackageManager.PERMISSION_GRANTED) {
            Log.w(TAG, "无法读取通讯录：号码为空或 READ_CONTACTS 未授权")
            return false
        }
        val lookupUri = Uri.withAppendedPath(
            ContactsContract.PhoneLookup.CONTENT_FILTER_URI,
            Uri.encode(number),
        )
        return runCatching {
            contentResolver.query(
                lookupUri,
                arrayOf(ContactsContract.PhoneLookup._ID),
                null,
                null,
                null,
            )?.use { cursor -> cursor.moveToFirst() } == true
        }.onFailure { Log.w(TAG, "读取通讯录失败", it) }.getOrDefault(false)
    }

    private fun matchesPhoneNumber(incoming: String, saved: String): Boolean {
        if (incoming.isBlank() || saved.isBlank()) return false
        if (PhoneNumberUtils.compare(incoming, saved)) return true
        val incomingDigits = PhoneNumberUtils.normalizeNumber(incoming)
        val savedDigits = PhoneNumberUtils.normalizeNumber(saved)
        val shorterLength = minOf(incomingDigits.length, savedDigits.length)
        return shorterLength >= MIN_SUFFIX_MATCH_DIGITS &&
            (incomingDigits.endsWith(savedDigits) || savedDigits.endsWith(incomingDigits))
    }

    private fun isEmergencyNumber(number: String): Boolean {
        val digits = PhoneNumberUtils.normalizeNumber(number)
        return EMERGENCY_NUMBERS.any { code ->
            digits == code || digits == "86$code" || digits == "1$code"
        }
    }

    private companion object {
        const val TAG = "3PonCallScreen"
        const val MIN_SUFFIX_MATCH_DIGITS = 7
        val EMERGENCY_NUMBERS = setOf("110", "119", "120", "122", "999", "911")
    }
}
