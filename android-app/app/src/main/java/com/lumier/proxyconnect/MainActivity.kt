package com.lumier.proxyconnect

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.edit

class MainActivity : AppCompatActivity() {

    companion object {
        const val PREFS_NAME = "LumierProxyPrefs"
        const val KEY_SERVER_IP = "server_ip"
        const val KEY_SERVER_PORT = "server_port"
        const val KEY_USERNAME = "username"
        const val VPN_REQUEST_CODE = 100
    }

    private lateinit var etServerIp: EditText
    private lateinit var etServerPort: EditText
    private lateinit var etUsername: EditText
    private lateinit var btnConnect: Button
    private lateinit var btnDisconnect: Button
    private lateinit var tvStatus: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        etServerIp = findViewById(R.id.etServerIp)
        etServerPort = findViewById(R.id.etServerPort)
        etUsername = findViewById(R.id.etUsername)
        btnConnect = findViewById(R.id.btnConnect)
        btnDisconnect = findViewById(R.id.btnDisconnect)
        tvStatus = findViewById(R.id.tvStatus)

        loadSavedSettings()

        btnConnect.setOnClickListener { startVpnConnection() }
        btnDisconnect.setOnClickListener { stopVpnConnection() }

        updateStatusDisplay()
    }

    override fun onResume() {
        super.onResume()
        updateStatusDisplay()
    }

    private fun loadSavedSettings() {
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        etServerIp.setText(prefs.getString(KEY_SERVER_IP, ""))
        etServerPort.setText(prefs.getString(KEY_SERVER_PORT, "8080"))
        etUsername.setText(prefs.getString(KEY_USERNAME, ""))
    }

    private fun saveSettings() {
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit {
            putString(KEY_SERVER_IP, etServerIp.text.toString().trim())
            putString(KEY_SERVER_PORT, etServerPort.text.toString().trim())
            putString(KEY_USERNAME, etUsername.text.toString().trim())
        }
    }

    private fun startVpnConnection() {
        val serverIp = etServerIp.text.toString().trim()
        val serverPort = etServerPort.text.toString().trim()
        val username = etUsername.text.toString().trim()

        if (serverIp.isEmpty()) {
            Toast.makeText(this, "Please enter server IP", Toast.LENGTH_SHORT).show()
            return
        }

        if (serverPort.isEmpty()) {
            Toast.makeText(this, "Please enter server port", Toast.LENGTH_SHORT).show()
            return
        }

        if (username.isEmpty()) {
            Toast.makeText(this, "Please enter a username", Toast.LENGTH_SHORT).show()
            return
        }

        saveSettings()

        // Request VPN permission
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            startActivityForResult(vpnIntent, VPN_REQUEST_CODE)
        } else {
            startProxyVpnService()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == Activity.RESULT_OK) {
                startProxyVpnService()
            } else {
                Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun startProxyVpnService() {
        val serverIp = etServerIp.text.toString().trim()
        val serverPort = etServerPort.text.toString().trim().toIntOrNull() ?: 8080
        val username = etUsername.text.toString().trim()

        val intent = Intent(this, ProxyVpnService::class.java).apply {
            action = ProxyVpnService.ACTION_CONNECT
            putExtra(ProxyVpnService.EXTRA_SERVER_IP, serverIp)
            putExtra(ProxyVpnService.EXTRA_SERVER_PORT, serverPort)
            putExtra(ProxyVpnService.EXTRA_USERNAME, username)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }

        Toast.makeText(this, "Connecting to proxy...", Toast.LENGTH_SHORT).show()
        updateStatusDisplay()
    }

    private fun stopVpnConnection() {
        val intent = Intent(this, ProxyVpnService::class.java).apply {
            action = ProxyVpnService.ACTION_DISCONNECT
        }
        startService(intent)
        Toast.makeText(this, "Disconnecting...", Toast.LENGTH_SHORT).show()

        // Update status after a short delay
        tvStatus.postDelayed({ updateStatusDisplay() }, 500)
    }

    private fun updateStatusDisplay() {
        val isConnected = ProxyVpnService.isRunning
        if (isConnected) {
            tvStatus.text = "Status: Connected"
            tvStatus.setTextColor(getColor(R.color.status_connected))
            btnConnect.isEnabled = false
            btnDisconnect.isEnabled = true
        } else {
            tvStatus.text = "Status: Disconnected"
            tvStatus.setTextColor(getColor(R.color.status_disconnected))
            btnConnect.isEnabled = true
            btnDisconnect.isEnabled = false
        }
    }
}
