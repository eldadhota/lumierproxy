package com.lumier.proxyconnect

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class ScreenUnlockReceiver : BroadcastReceiver() {

    companion object {
        var onScreenUnlocked: (() -> Unit)? = null
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_USER_PRESENT) {
            onScreenUnlocked?.invoke()
        }
    }
}
