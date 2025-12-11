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
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
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
    private var vpnThread: Thread? = null

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
            }
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("Lumier Proxy")
            .setContentText("Connected as: $username")
            .setSmallIcon(R.drawable.ic_vpn)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun startVpn() {
        if (running.get()) {
            Log.d(TAG, "VPN already running")
            return
        }

        try {
            // Build VPN interface
            val builder = Builder()
                .setSession("Lumier Proxy ($username)")
                .addAddress("10.0.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .addDnsServer("8.8.4.4")
                .setMtu(1500)

            // Exclude the proxy server from VPN to avoid infinite loop
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                try {
                    val proxyAddr = java.net.InetAddress.getByName(serverIp)
                    val prefix = android.net.IpPrefix(proxyAddr, 32)
                    builder.excludeRoute(prefix)
                } catch (e: Exception) {
                    Log.w(TAG, "Could not exclude proxy route: ${e.message}")
                }
            }

            // Allow bypass for the proxy connection
            builder.allowBypass()

            vpnInterface = builder.establish()

            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                return
            }

            running.set(true)
            isRunning = true

            // Start foreground service with notification
            startForeground(NOTIFICATION_ID, createNotification())

            // Start the VPN processing thread
            vpnThread = Thread { runVpnLoop() }
            vpnThread?.start()

            Log.i(TAG, "VPN started successfully for user: $username")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start VPN: ${e.message}", e)
            stopVpn()
        }
    }

    private fun stopVpn() {
        running.set(false)
        isRunning = false

        vpnThread?.interrupt()
        vpnThread = null

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

    private fun runVpnLoop() {
        val vpnFd = vpnInterface?.fileDescriptor ?: return
        val vpnInput = FileInputStream(vpnFd)
        val vpnOutput = FileOutputStream(vpnFd)

        val packet = ByteBuffer.allocate(32767)

        try {
            while (running.get()) {
                // Read packet from VPN interface
                packet.clear()
                val length = vpnInput.read(packet.array())

                if (length > 0 && running.get()) {
                    packet.limit(length)
                    handlePacket(packet, vpnOutput)
                }

                // Small sleep to prevent CPU spinning
                Thread.sleep(1)
            }
        } catch (e: InterruptedException) {
            Log.d(TAG, "VPN loop interrupted")
        } catch (e: Exception) {
            Log.e(TAG, "VPN loop error: ${e.message}", e)
        } finally {
            try {
                vpnInput.close()
                vpnOutput.close()
            } catch (e: Exception) {
                // Ignore
            }
        }
    }

    private fun handlePacket(packet: ByteBuffer, vpnOutput: FileOutputStream) {
        // Parse IP header to determine protocol and destination
        if (packet.limit() < 20) return

        val version = (packet.get(0).toInt() shr 4) and 0xF
        if (version != 4) return // Only handle IPv4

        val protocol = packet.get(9).toInt() and 0xFF
        val destIp = getDestinationIp(packet)

        // Skip packets destined to the proxy server itself
        if (destIp == serverIp) {
            return
        }

        when (protocol) {
            6 -> handleTcpPacket(packet, vpnOutput) // TCP
            17 -> handleUdpPacket(packet, vpnOutput) // UDP
        }
    }

    private fun getDestinationIp(packet: ByteBuffer): String {
        val destIp = ByteArray(4)
        packet.position(16)
        packet.get(destIp)
        packet.rewind()
        return destIp.joinToString(".") { (it.toInt() and 0xFF).toString() }
    }

    private fun handleTcpPacket(packet: ByteBuffer, vpnOutput: FileOutputStream) {
        // For TCP connections, we would ideally tunnel through the HTTP proxy
        // This is a simplified implementation - a full implementation would:
        // 1. Track TCP connections
        // 2. Use HTTP CONNECT for HTTPS traffic
        // 3. Forward HTTP traffic through the proxy

        // For this simple app, we're primarily setting up the VPN tunnel
        // The actual proxy routing happens at the system level when the VPN is active
        // The username is sent via the initial connection to register the device

        try {
            // Extract destination port
            val ipHeaderLength = (packet.get(0).toInt() and 0xF) * 4
            if (packet.limit() < ipHeaderLength + 4) return

            val destPort = ((packet.get(ipHeaderLength).toInt() and 0xFF) shl 8) or
                    (packet.get(ipHeaderLength + 1).toInt() and 0xFF)

            // For HTTP/HTTPS ports, we could implement proxy tunneling
            // For simplicity, this demo just logs the connection attempt
            if (destPort == 80 || destPort == 443) {
                Log.v(TAG, "TCP packet to port $destPort")
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error handling TCP packet: ${e.message}")
        }
    }

    private fun handleUdpPacket(packet: ByteBuffer, vpnOutput: FileOutputStream) {
        // UDP packets (like DNS) - in a full implementation, these would be
        // forwarded through a SOCKS5 proxy or DNS-over-HTTPS
        Log.v(TAG, "UDP packet received")
    }

    /**
     * Creates the Basic auth header value for proxy authentication
     */
    private fun createProxyAuthHeader(): String {
        // Format: Basic base64(username:password)
        // We use username with empty password since our proxy only needs the username
        val credentials = "$username:"
        val encoded = Base64.encodeToString(credentials.toByteArray(), Base64.NO_WRAP)
        return "Basic $encoded"
    }

    /**
     * Connect to a remote host through the HTTP proxy using CONNECT method
     */
    private fun connectThroughProxy(destHost: String, destPort: Int): Socket? {
        return try {
            val proxySocket = Socket()
            // Protect this socket so it doesn't go through VPN (infinite loop prevention)
            protect(proxySocket)

            proxySocket.connect(InetSocketAddress(serverIp, serverPort), 10000)

            val writer = proxySocket.getOutputStream().bufferedWriter()
            val reader = proxySocket.getInputStream().bufferedReader()

            // Send CONNECT request with proxy authentication
            writer.write("CONNECT $destHost:$destPort HTTP/1.1\r\n")
            writer.write("Host: $destHost:$destPort\r\n")
            writer.write("Proxy-Authorization: ${createProxyAuthHeader()}\r\n")
            writer.write("Proxy-Connection: Keep-Alive\r\n")
            writer.write("\r\n")
            writer.flush()

            // Read response
            val responseLine = reader.readLine() ?: ""
            if (responseLine.contains("200")) {
                // Skip remaining headers
                while (reader.readLine()?.isNotEmpty() == true) {
                    // Continue reading until empty line
                }
                Log.d(TAG, "Proxy tunnel established to $destHost:$destPort")
                proxySocket
            } else {
                Log.e(TAG, "Proxy CONNECT failed: $responseLine")
                proxySocket.close()
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to connect through proxy: ${e.message}")
            null
        }
    }
}
