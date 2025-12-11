package com.lumier.proxyconnect

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Base64
import android.util.Log
import androidx.core.app.NotificationCompat
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.util.concurrent.atomic.AtomicBoolean

class ProxyVpnService : VpnService() {

    companion object {
        const val TAG = "ProxyVpnService"
        const val ACTION_CONNECT = "com.lumier.proxyconnect.CONNECT"
        const val ACTION_DISCONNECT = "com.lumier.proxyconnect.DISCONNECT"
        const val EXTRA_SERVER_IP = "server_ip"
        const val EXTRA_SERVER_PORT = "server_port"
        const val EXTRA_USERNAME = "username"
        const val NOTIFICATION_CHANNEL_ID = "lumier_vpn_channel"
        const val NOTIFICATION_ID = 1

        @Volatile
        var isRunning = false
            private set
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var serverIp: String = ""
    private var serverPort: Int = 8080
    private var username: String = ""
    private val running = AtomicBoolean(false)
    private var keepAliveThread: Thread? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                serverIp = intent.getStringExtra(EXTRA_SERVER_IP) ?: ""
                serverPort = intent.getIntExtra(EXTRA_SERVER_PORT, 8080)
                username = intent.getStringExtra(EXTRA_USERNAME) ?: ""

                if (serverIp.isNotEmpty() && username.isNotEmpty()) {
                    startVpn()
                } else {
                    Log.e(TAG, "Missing server IP or username")
                    stopSelf()
                }
            }
            ACTION_DISCONNECT -> {
                stopVpn()
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "Lumier Proxy VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "VPN connection status"
                setShowBadge(false)
            }
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(status: String = "Connected"): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("Lumier Proxy")
            .setContentText("$status as: $username")
            .setSmallIcon(R.drawable.ic_vpn)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun startVpn() {
        if (running.get()) {
            Log.d(TAG, "VPN already running")
            return
        }

        // Start foreground FIRST (required on Android 14+)
        startForeground(NOTIFICATION_ID, createNotification("Connecting"))

        try {
            // Build a minimal VPN interface that doesn't route traffic
            // This just establishes identity with the proxy server
            val builder = Builder()
                .setSession("Lumier Proxy ($username)")
                .addAddress("10.255.255.1", 32)
                .setMtu(1500)
                .setBlocking(false)

            // Don't add routes - we don't want to capture traffic
            // The VPN is just for device registration/identification

            // Allow all apps to bypass this VPN
            builder.allowBypass()

            // Exclude all traffic by not adding any routes
            // Or add a dummy route to a non-routable address
            builder.addRoute("10.255.255.0", 24)

            vpnInterface = builder.establish()

            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            running.set(true)
            isRunning = true

            // Update notification
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.notify(NOTIFICATION_ID, createNotification("Connected"))

            // Start keep-alive thread that registers with proxy server
            keepAliveThread = Thread { runKeepAlive() }
            keepAliveThread?.start()

            Log.i(TAG, "VPN started successfully for user: $username")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start VPN: ${e.message}", e)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun stopVpn() {
        running.set(false)
        isRunning = false

        keepAliveThread?.interrupt()
        keepAliveThread = null

        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface: ${e.message}")
        }
        vpnInterface = null

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()

        Log.i(TAG, "VPN stopped")
    }

    private fun runKeepAlive() {
        // Register with the proxy server immediately
        registerWithProxy()

        // Then periodically ping to keep registration alive
        try {
            while (running.get()) {
                Thread.sleep(30000) // Every 30 seconds
                if (running.get()) {
                    registerWithProxy()
                }
            }
        } catch (e: InterruptedException) {
            Log.d(TAG, "Keep-alive interrupted")
        }
    }

    private fun registerWithProxy() {
        try {
            // Make a request through the proxy to register this device
            val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress(serverIp, serverPort))
            val url = URL("http://lumier.local/register")

            val connection = url.openConnection(proxy) as HttpURLConnection
            connection.connectTimeout = 10000
            connection.readTimeout = 10000
            connection.requestMethod = "GET"

            // Add proxy authentication with username
            val credentials = "$username:"
            val encoded = Base64.encodeToString(credentials.toByteArray(), Base64.NO_WRAP)
            connection.setRequestProperty("Proxy-Authorization", "Basic $encoded")

            try {
                connection.connect()
                val responseCode = connection.responseCode
                Log.d(TAG, "Registration ping: $responseCode")
            } catch (e: Exception) {
                // Connection might fail but proxy still sees the auth header
                Log.d(TAG, "Registration ping sent (response: ${e.message})")
            } finally {
                connection.disconnect()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to register with proxy: ${e.message}")
        }
    }
}
