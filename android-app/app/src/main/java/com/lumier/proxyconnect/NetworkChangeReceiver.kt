package com.lumier.proxyconnect

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build

class NetworkChangeReceiver : BroadcastReceiver() {

    companion object {
        var onWifiConnected: (() -> Unit)? = null
        private var wasConnected = false
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (isWifiConnected(context)) {
            // Only trigger if we're transitioning to connected state
            if (!wasConnected) {
                wasConnected = true
                onWifiConnected?.invoke()
            }
        } else {
            wasConnected = false
        }
    }

    private fun isWifiConnected(context: Context): Boolean {
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val network = connectivityManager.activeNetwork ?: return false
            val capabilities = connectivityManager.getNetworkCapabilities(network) ?: return false
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
        } else {
            @Suppress("DEPRECATION")
            val networkInfo = connectivityManager.activeNetworkInfo
            networkInfo?.type == ConnectivityManager.TYPE_WIFI && networkInfo.isConnected
        }
    }
}
