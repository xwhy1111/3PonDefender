package com.threepon.defender

import android.app.Service
import android.content.Intent
import android.os.IBinder

class ShizukuCommandService : Service() {
    private val binder = object : IShizukuCommand.Stub() {
        override fun exec(command: Array<String>): String {
            val process = ProcessBuilder(command.toList())
                .redirectErrorStream(true)
                .start()
            val output = process.inputStream.bufferedReader().use { it.readText() }
            val exit = process.waitFor()
            return "exit=$exit\n$output"
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder
}
