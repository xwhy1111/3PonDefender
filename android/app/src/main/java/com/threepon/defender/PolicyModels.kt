package com.threepon.defender

data class DeviceCapability(
    val key: String,
    val supported: Boolean,
    val reason: String? = null,
)

data class OwnerPolicyValue(
    val key: String,
    val value: Any,
)

data class BasicControlPolicy(
    val installationApprovalRequired: Boolean = true,
    val defaultNetworkMode: String = "deny_unlisted",
    val defenderSelfProtection: Boolean = true,
    val callScreeningEnabled: Boolean = true,
    val callAllowlist: List<String> = listOf("110", "120", "119"),
    val contactsOnlyCalls: Boolean = false,
    val suspendedPackages: List<String> = emptyList(),
)

data class ConsentRecord(
    val version: String,
    val acceptedAtEpochMillis: Long,
    val featureSummaryHash: String,
)
