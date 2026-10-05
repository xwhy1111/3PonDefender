package com.threepon.defender

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.app.role.RoleManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val store = PairingStore(applicationContext)
        if (store.read() != null) {
            DefenderPollingService.start(applicationContext)
            DefenderUpdateScheduler.schedule(applicationContext)
        }
        setContent {
            DefenderTheme {
                DefenderApp(DeviceOwnerController(this), store)
            }
        }
    }
}

@Composable
private fun DefenderTheme(content: @Composable () -> Unit) {
    MaterialTheme(content = content)
}

@Composable
private fun DefenderApp(controller: DeviceOwnerController, store: PairingStore) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()
    val preferences = remember { context.getSharedPreferences("policy", android.content.Context.MODE_PRIVATE) }
    var owner by remember { mutableStateOf(controller.isDeviceOwner()) }
    var pairing by remember { mutableStateOf(store.read()) }
    var serverOnline by remember { mutableStateOf(readServerOnline(preferences, pairing != null)) }
    var contactsPermissionGranted by remember {
        mutableStateOf(context.checkSelfPermission(Manifest.permission.READ_CONTACTS) == PackageManager.PERMISSION_GRANTED)
    }
    var callScreeningRequired by remember { mutableStateOf(preferences.getBoolean("call_screening_required", false)) }
    var contactsOnlyCallsEnabled by remember { mutableStateOf(preferences.getBoolean("contacts_only_calls_enabled", false)) }
    val roleManager = remember { context.getSystemService(RoleManager::class.java) }
    var callScreeningRoleHeld by remember {
        mutableStateOf(roleManager.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING) && roleManager.isRoleHeld(RoleManager.ROLE_CALL_SCREENING))
    }
    var pendingPayload by remember { mutableStateOf<PairingPayload?>(null) }
    var consented by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf("") }
    var settingsOpen by remember { mutableStateOf(false) }
    var authDialogOpen by remember { mutableStateOf(false) }
    var adminPassword by remember { mutableStateOf("") }
    var initialScanStarted by remember { mutableStateOf(false) }
    var batteryUnrestricted by remember { mutableStateOf(XiaomiBackgroundProtection.isBatteryUnrestricted(context)) }
    val lifecycleOwner = LocalLifecycleOwner.current

    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                owner = controller.isDeviceOwner()
                batteryUnrestricted = XiaomiBackgroundProtection.isBatteryUnrestricted(context)
                contactsPermissionGranted = context.checkSelfPermission(Manifest.permission.READ_CONTACTS) == PackageManager.PERMISSION_GRANTED
                callScreeningRequired = preferences.getBoolean("call_screening_required", false)
                contactsOnlyCallsEnabled = preferences.getBoolean("contacts_only_calls_enabled", false)
                callScreeningRoleHeld = roleManager.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING) && roleManager.isRoleHeld(RoleManager.ROLE_CALL_SCREENING)
                serverOnline = readServerOnline(preferences, store.read() != null)
                pairing = store.read()
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    LaunchedEffect(pairing?.deviceId) {
        while (true) {
            serverOnline = readServerOnline(preferences, pairing != null)
            val required = preferences.getBoolean("call_screening_required", false)
            if (!required && callScreeningRequired) {
                preferences.edit()
                    .putBoolean("call_screening_role_prompt_attempted", false)
                    .putBoolean("contacts_permission_prompt_attempted", false)
                    .apply()
            }
            callScreeningRequired = required
            contactsOnlyCallsEnabled = preferences.getBoolean("contacts_only_calls_enabled", false)
            contactsPermissionGranted = context.checkSelfPermission(Manifest.permission.READ_CONTACTS) == PackageManager.PERMISSION_GRANTED
            callScreeningRoleHeld = roleManager.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING) && roleManager.isRoleHeld(RoleManager.ROLE_CALL_SCREENING)
            owner = controller.isDeviceOwner()
            delay(2_000)
        }
    }

    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        val contents = result.contents
        if (contents.isNullOrBlank()) {
            if (pairing == null) error = "未扫描到二维码，请点齿轮后重新扫码。"
            return@rememberLauncherForActivityResult
        }
        runCatching { PairingPayload.fromJson(contents) }
            .onSuccess {
                pendingPayload = it
                consented = false
                error = ""
                settingsOpen = false
            }
            .onFailure {
                pendingPayload = null
                error = it.message ?: "二维码格式无效"
            }
    }

    fun launchScanner() {
        error = ""
        scanLauncher.launch(ScanOptions().apply {
            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            setPrompt("扫描管控端生成的配对二维码")
            setBeepEnabled(false)
            setOrientationLocked(false)
        })
    }

    LaunchedEffect(pairing?.deviceId) {
        if (pairing == null && !initialScanStarted) {
            initialScanStarted = true
            delay(450)
            launchScanner()
        }
    }

    val contactsPermissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        contactsPermissionGranted = granted
        error = if (granted) "通讯录权限已允许。" else "通讯录权限未允许；通讯录号码不会自动放行。"
    }
    val callScreeningRoleLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        callScreeningRoleHeld = roleManager.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING) && roleManager.isRoleHeld(RoleManager.ROLE_CALL_SCREENING)
        error = if (callScreeningRoleHeld) "来电筛选已启用。" else "系统未将 3Pon Defender 设为来电筛选应用；电话筛选策略不会生效。"
    }

    LaunchedEffect(pairing?.deviceId, callScreeningRequired, contactsOnlyCallsEnabled, callScreeningRoleHeld, contactsPermissionGranted, owner) {
        if (pairing == null || !callScreeningRequired) return@LaunchedEffect
        val settings = preferences.edit()
        if (!roleManager.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING)) {
            error = "此系统不提供 Android 来电筛选角色，来电策略无法由 3Pon Defender 执行。"
            return@LaunchedEffect
        }
        if (!callScreeningRoleHeld && !preferences.getBoolean("call_screening_role_prompt_attempted", false)) {
            settings.putBoolean("call_screening_role_prompt_attempted", true).commit()
            delay(500)
            callScreeningRoleLauncher.launch(roleManager.createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING))
            return@LaunchedEffect
        }
        if (contactsOnlyCallsEnabled && callScreeningRoleHeld && !contactsPermissionGranted &&
            !preferences.getBoolean("contacts_permission_prompt_attempted", false)
        ) {
            settings.putBoolean("contacts_permission_prompt_attempted", true).commit()
            delay(500)
            contactsPermissionLauncher.launch(Manifest.permission.READ_CONTACTS)
        }
    }

    fun claimPairing() {
        val payload = pendingPayload ?: return
        if (!consented) {
            error = "请先阅读并同意设备管控功能，再绑定管控端。"
            return
        }
        busy = true
        error = ""
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { PairingClient().claim(context.applicationContext, payload, consented) }
            }
            result.onSuccess { config ->
                store.save(config)
                pairing = config
                pendingPayload = null
                serverOnline = false
                DefenderPollingService.start(context)
                DefenderUpdateScheduler.schedule(context)
                DefenderUpdateScheduler.checkNow(context)
            }.onFailure { failure ->
                error = failure.message ?: "配对失败，请重新生成二维码"
            }
            busy = false
        }
    }

    fun verifyAdminPassword() {
        val config = pairing
        if (config == null) {
            authDialogOpen = false
            settingsOpen = true
            adminPassword = ""
            return
        }
        busy = true
        error = ""
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { AdminAuthClient().verifyPassword(config, adminPassword) }
            }
            result.onSuccess { valid ->
                if (valid) {
                    authDialogOpen = false
                    settingsOpen = true
                    adminPassword = ""
                } else {
                    error = "管理员密码不正确"
                }
            }.onFailure { failure ->
                error = failure.message ?: "无法验证管理员密码，请检查服务器连接"
            }
            busy = false
        }
    }

    Surface(modifier = Modifier.fillMaxSize(), color = Color(0xFFF4F7F6)) {
        Box(modifier = Modifier.fillMaxSize()) {
            if (settingsOpen) {
                SettingsPage(
                    owner = owner,
                    pairing = pairing,
                    serverOnline = serverOnline,
                    batteryUnrestricted = batteryUnrestricted,
                    contactsPermissionGranted = contactsPermissionGranted,
                    callScreeningRoleHeld = callScreeningRoleHeld,
                    onBack = { settingsOpen = false; error = "" },
                    onRescan = { launchScanner() },
                    onRequestContacts = { contactsPermissionLauncher.launch(Manifest.permission.READ_CONTACTS) },
                    onRequestCallScreeningRole = {
                        if (roleManager.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING)) {
                            callScreeningRoleLauncher.launch(roleManager.createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING))
                        } else {
                            error = "此系统不支持第三方来电筛选角色。"
                        }
                    },
                    onOpenAutoStart = { XiaomiBackgroundProtection.openAutoStartSettings(context) },
                    onOpenBattery = { XiaomiBackgroundProtection.openBatterySettings(context) },
                    onRegisterOwner = {
                        (context as? android.app.Activity)?.let { activity ->
                            ShizukuProvisioning.register(activity) { result ->
                                error = result
                                owner = controller.isDeviceOwner()
                            }
                        }
                    },
                    error = error,
                )
            } else {
                IconButton(
                        onClick = {
                            error = ""
                            if (pairing == null) {
                                if (initialScanStarted) settingsOpen = true else launchScanner()
                            } else {
                                authDialogOpen = true
                        }
                    },
                    modifier = Modifier.align(Alignment.TopEnd).padding(14.dp),
                ) {
                    Icon(Icons.Default.Settings, contentDescription = "管理员设置", tint = Color(0xFF34423E))
                }

                if (pendingPayload == null) {
                    Column(
                        modifier = Modifier.align(Alignment.Center).padding(horizontal = 30.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(14.dp),
                    ) {
                        Image(
                            painter = painterResource(R.drawable.threepon_logo),
                            contentDescription = "3Pon Defender Logo",
                            contentScale = ContentScale.Crop,
                            modifier = Modifier.size(116.dp).clip(RoundedCornerShape(28.dp)),
                        )
                        Text("3Pon Defender", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold, color = Color(0xFF26322F))
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            val statusColor = if (serverOnline) Color(0xFF16864A) else Color(0xFFC62828)
                            Surface(color = statusColor, shape = CircleShape, modifier = Modifier.size(9.dp)) {}
                            Text(if (serverOnline) "在线" else "离线", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, color = statusColor)
                        }
                        if (pairing == null && !owner) {
                            Spacer(Modifier.height(4.dp))
                            Text("请先完成设备所有者注册，再扫描管控端二维码。", color = Color(0xFF68736F), style = MaterialTheme.typography.bodyMedium)
                            Text("首次启动会自动打开扫码器；点击右上角齿轮可重新扫码。", color = Color(0xFF68736F), style = MaterialTheme.typography.bodySmall)
                        }
                        if (error.isNotBlank()) {
                            Text(error, color = Color(0xFFB3261E), style = MaterialTheme.typography.bodySmall)
                        }
                    }
                } else {
                    PairingConfirmation(
                        payload = pendingPayload!!,
                        consented = consented,
                        owner = owner,
                        busy = busy,
                        error = error,
                        onConsent = { consented = it },
                        onClaim = { claimPairing() },
                        onCancel = { pendingPayload = null; error = "" },
                        onRegisterOwner = {
                            (context as? android.app.Activity)?.let { activity ->
                                ShizukuProvisioning.register(activity) { result ->
                                    error = result
                                    owner = controller.isDeviceOwner()
                                }
                            }
                        },
                    )
                }
            }
        }
    }

    if (authDialogOpen) {
        AlertDialog(
            onDismissRequest = { authDialogOpen = false; adminPassword = "" },
            title = { Text("管理员验证") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("输入管控端网页管理员密码以打开设置。")
                    OutlinedTextField(
                        value = adminPassword,
                        onValueChange = { adminPassword = it },
                        label = { Text("管理员密码") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                    )
                    if (error.isNotBlank()) Text(error, color = Color(0xFFB3261E))
                }
            },
            confirmButton = {
                TextButton(onClick = { verifyAdminPassword() }, enabled = !busy && adminPassword.isNotBlank()) {
                    if (busy) CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp) else Text("验证")
                }
            },
            dismissButton = { TextButton(onClick = { authDialogOpen = false; adminPassword = "" }) { Text("取消") } },
        )
    }
}

@Composable
private fun PairingConfirmation(
    payload: PairingPayload,
    consented: Boolean,
    owner: Boolean,
    busy: Boolean,
    error: String,
    onConsent: (Boolean) -> Unit,
    onClaim: () -> Unit,
    onCancel: () -> Unit,
    onRegisterOwner: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
        horizontalAlignment = Alignment.Start,
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("确认绑定管控端", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text("服务器地址：${payload.baseUrl}")
        Text("绑定后，管控端可按您同意的功能管理设备策略、应用、电话和联网状态。设备会每 10 秒连接服务器检查策略与软件更新。")
        Row(verticalAlignment = Alignment.CenterVertically) {
            androidx.compose.material3.Checkbox(checked = consented, onCheckedChange = onConsent)
            Text("我已阅读并自愿同意上述管控功能")
        }
        if (!owner) {
            Text("当前应用还不是 Device Owner，需要先完成注册。", color = Color(0xFFB3261E))
            OutlinedButton(onClick = onRegisterOwner) { Text("使用 Shizuku 注册 Device Owner") }
        }
        if (error.isNotBlank()) Text(error, color = Color(0xFFB3261E))
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Button(onClick = onClaim, enabled = owner && consented && !busy) {
                if (busy) CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp) else Text("同意并绑定")
            }
            TextButton(onClick = onCancel, enabled = !busy) { Text("取消") }
        }
    }
}

@Composable
private fun SettingsPage(
    owner: Boolean,
    pairing: PairingConfig?,
    serverOnline: Boolean,
    batteryUnrestricted: Boolean,
    contactsPermissionGranted: Boolean,
    callScreeningRoleHeld: Boolean,
    onBack: () -> Unit,
    onRescan: () -> Unit,
    onRequestContacts: () -> Unit,
    onRequestCallScreeningRole: () -> Unit,
    onOpenAutoStart: () -> Unit,
    onOpenBattery: () -> Unit,
    onRegisterOwner: () -> Unit,
    error: String,
) {
    Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) { Icon(Icons.Default.ArrowBack, contentDescription = "返回") }
            Text("管理员设置", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.height(14.dp))
        SettingsCard(title = "设备信息") {
            SettingsLine("设备所有者", if (owner) "已注册" else "未注册")
            SettingsLine("服务器", if (serverOnline) "在线" else "离线")
            SettingsLine("自动更新", if (pairing != null) "已开启 · 每 10 秒检查" else "未绑定")
            pairing?.let {
                SettingsLine("管控端", it.baseUrl)
                SettingsLine("设备编号", it.deviceId)
            }
        }
        Spacer(Modifier.height(12.dp))
        SettingsCard(title = "重新绑定") {
            Text("扫描管控端新生成的一次性二维码。重新绑定前需要再次确认同意。")
            Button(onClick = onRescan, modifier = Modifier.fillMaxWidth()) { Text(if (pairing == null) "扫描管控端二维码" else "重新扫码") }
            if (!owner) OutlinedButton(onClick = onRegisterOwner, modifier = Modifier.fillMaxWidth()) { Text("使用 Shizuku 注册 Device Owner") }
        }
        Spacer(Modifier.height(12.dp))
        SettingsCard(title = "电话筛选") {
            SettingsLine("系统来电筛选角色", if (callScreeningRoleHeld) "已启用" else "未启用")
            if (!callScreeningRoleHeld) {
                Text("Android/HyperOS 只有在用户将 3Pon Defender 设为来电筛选应用后，才会把来电交给本应用处理。")
                OutlinedButton(onClick = onRequestCallScreeningRole) { Text("启用来电筛选") }
            }
            SettingsLine("通讯录读取权限", if (contactsPermissionGranted) "已授权" else "未授权")
            Text("开启“仅允许通讯录来电”后，Defender 在本机读取联系人电话号码并判断是否匹配，不会上传联系人。需要同时授予通讯录权限并启用上方系统来电筛选角色。")
            if (!contactsPermissionGranted) OutlinedButton(onClick = onRequestContacts) { Text("允许读取通讯录") }
        }
        Spacer(Modifier.height(12.dp))
        SettingsCard(title = "小米后台运行") {
            SettingsLine("电池策略", if (batteryUnrestricted) "不受限制" else "需要设置")
            Text("HyperOS 可能限制后台轮询。请允许自启动，并将电池策略设置为不受限制。")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onOpenAutoStart) { Text("自启动设置") }
                OutlinedButton(onClick = onOpenBattery) { Text("电池设置") }
            }
        }
        Spacer(Modifier.height(12.dp))
        SettingsCard(title = "版本") {
            SettingsLine("3Pon Defender", "${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
            SettingsLine("服务连接", if (serverOnline) "在线" else "等待轮询")
        }
        if (error.isNotBlank()) {
            Spacer(Modifier.height(12.dp))
            Text(error, color = Color(0xFFB3261E))
        }
    }
}

@Composable
private fun SettingsCard(title: String, content: @Composable () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(18.dp)) {
        Column(modifier = Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            content()
        }
    }
}

@Composable
private fun SettingsLine(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
        Text(label, color = Color(0xFF66746F))
        Text(value, fontWeight = FontWeight.SemiBold)
    }
}

private fun readServerOnline(preferences: android.content.SharedPreferences, paired: Boolean): Boolean {
    if (!paired || !preferences.getBoolean("server_online", false)) return false
    val lastPollAt = preferences.getLong("server_last_poll_at", 0L)
    return lastPollAt > 0 && System.currentTimeMillis() - lastPollAt < 35_000L
}
