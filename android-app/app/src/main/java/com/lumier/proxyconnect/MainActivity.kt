package com.lumier.proxyconnect

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.wifi.WifiManager
import android.os.Bundle
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.edit
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL

class MainActivity : AppCompatActivity() {

    companion object {
        const val PREFS_NAME = "LumierProxyPrefs"
        const val KEY_SERVER_IP = "server_ip"
        const val KEY_SERVER_PORT = "server_port"
        const val KEY_USERNAME = "username"
        const val KEY_PROXY_INDEX = "proxy_index"
        const val KEY_SESSION_TOKEN = "session_token"
        const val KEY_ROLLOUT_MODE = "rollout_mode"  // Locks username and proxy selection

        // Fallback passwords (used if server is unreachable)
        const val FALLBACK_ADMIN_PASSWORD = "Drnda123"
        val FALLBACK_SUPERVISOR_PASSWORDS = mapOf(
            "DobroJeMirko321a" to "Mirko",
            "SupervisorAna123" to "Ana",
            "SupervisorMarko456" to "Marko",
            "SupervisorIvan789" to "Ivan"
        )
    }

    private lateinit var etServerIp: EditText
    private lateinit var etServerPort: EditText
    private lateinit var etUsername: EditText
    private lateinit var spinnerProxy: Spinner
    private lateinit var btnRefresh: Button
    private lateinit var btnConnect: Button
    private lateinit var btnRegister: Button
    private lateinit var btnChangeProxy: Button
    private lateinit var btnCheckIp: Button
    private lateinit var tvStatus: TextView
    private lateinit var tvWhoAmI: TextView

    private val proxyList = mutableListOf<ProxyItem>()
    private var sessionToken: String? = null
    private var isRolloutMode = false
    private var detectedProxyName: String? = null  // Store detected proxy from Check IP

    // Broadcast receivers for automatic IP checks
    private val networkChangeReceiver = NetworkChangeReceiver()
    private val screenUnlockReceiver = ScreenUnlockReceiver()
    private var receiversRegistered = false

    data class ProxyItem(val index: Int, val name: String) {
        override fun toString() = name
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        etServerIp = findViewById(R.id.etServerIp)
        etServerPort = findViewById(R.id.etServerPort)
        etUsername = findViewById(R.id.etUsername)
        spinnerProxy = findViewById(R.id.spinnerProxy)
        btnRefresh = findViewById(R.id.btnRefresh)
        btnConnect = findViewById(R.id.btnConnect)
        btnRegister = findViewById(R.id.btnRegister)
        btnChangeProxy = findViewById(R.id.btnChangeProxy)
        btnCheckIp = findViewById(R.id.btnCheckIp)
        tvStatus = findViewById(R.id.tvStatus)
        tvWhoAmI = findViewById(R.id.tvWhoAmI)

        loadSavedSettings()
        applyRolloutMode()

        btnRefresh.setOnClickListener { fetchProxies() }
        btnConnect.setOnClickListener { connectDevice() }
        btnRegister.setOnClickListener { registerDevice() }
        btnChangeProxy.setOnClickListener { changeProxy() }
        btnCheckIp.setOnClickListener { checkWhoAmI() }

        // Set up callbacks for automatic IP checks
        NetworkChangeReceiver.onWifiConnected = {
            runOnUiThread {
                Toast.makeText(this, "WiFi connected - checking IP...", Toast.LENGTH_SHORT).show()
                checkWhoAmI()
            }
        }
        ScreenUnlockReceiver.onScreenUnlocked = {
            runOnUiThread {
                // Only check if app is visible
                if (!isFinishing && !isDestroyed) {
                    checkWhoAmI()
                }
            }
        }

        // Register broadcast receivers
        registerReceivers()

        // Auto-fetch proxies if server is configured
        if (etServerIp.text.isNotEmpty()) {
            fetchProxies()
        }
    }

    private fun registerReceivers() {
        if (receiversRegistered) return

        try {
            // Register for WiFi/connectivity changes
            val networkFilter = IntentFilter().apply {
                addAction(ConnectivityManager.CONNECTIVITY_ACTION)
                addAction(WifiManager.NETWORK_STATE_CHANGED_ACTION)
            }
            registerReceiver(networkChangeReceiver, networkFilter)

            // Register for screen unlock
            val screenFilter = IntentFilter(Intent.ACTION_USER_PRESENT)
            registerReceiver(screenUnlockReceiver, screenFilter)

            receiversRegistered = true
        } catch (e: Exception) {
            // Ignore registration errors
        }
    }

    private fun unregisterReceivers() {
        if (!receiversRegistered) return

        try {
            unregisterReceiver(networkChangeReceiver)
            unregisterReceiver(screenUnlockReceiver)
            receiversRegistered = false
        } catch (e: Exception) {
            // Ignore unregistration errors
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceivers()
    }

    private fun loadSavedSettings() {
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        etServerIp.setText(prefs.getString(KEY_SERVER_IP, "192.168.50.60"))
        etServerPort.setText(prefs.getString(KEY_SERVER_PORT, "8888"))
        etUsername.setText(prefs.getString(KEY_USERNAME, ""))
        sessionToken = prefs.getString(KEY_SESSION_TOKEN, null)
        isRolloutMode = prefs.getBoolean(KEY_ROLLOUT_MODE, false)
    }

    private fun applyRolloutMode() {
        if (isRolloutMode) {
            // Lock all settings in rollout mode - only Connect and Check IP available to users
            etServerIp.isEnabled = false
            etServerPort.isEnabled = false
            etUsername.isEnabled = false
            spinnerProxy.isEnabled = false
            btnRefresh.visibility = View.GONE
            tvStatus.text = "Rollout Mode - Settings locked"
            tvStatus.setTextColor(getColor(R.color.primary))
        } else {
            etServerIp.isEnabled = true
            etServerPort.isEnabled = true
            etUsername.isEnabled = true
            spinnerProxy.isEnabled = true
            btnRefresh.visibility = View.VISIBLE
        }
    }

    private fun temporarilyUnlockForSupervisor() {
        // Temporarily unlock proxy selection for supervisor to make changes
        spinnerProxy.isEnabled = true
        btnRefresh.visibility = View.VISIBLE
    }

    private fun relockAfterSupervisorChange() {
        // Re-lock fields after supervisor makes changes (if in rollout mode)
        if (isRolloutMode) {
            spinnerProxy.isEnabled = false
            btnRefresh.visibility = View.GONE
        }
    }

    private fun saveSettings() {
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit {
            putString(KEY_SERVER_IP, etServerIp.text.toString().trim())
            putString(KEY_SERVER_PORT, etServerPort.text.toString().trim())
            putString(KEY_USERNAME, etUsername.text.toString().trim())
            putInt(KEY_PROXY_INDEX, (spinnerProxy.selectedItem as? ProxyItem)?.index ?: 0)
            sessionToken?.let { putString(KEY_SESSION_TOKEN, it) }
        }
    }

    private fun saveSessionToken(token: String) {
        sessionToken = token
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit { putString(KEY_SESSION_TOKEN, token) }
    }

    private fun getServerUrl(): String {
        val ip = etServerIp.text.toString().trim()
        val port = etServerPort.text.toString().trim().ifEmpty { "8081" }
        return "http://$ip:$port"
    }

    private fun addAppHeaders(connection: HttpURLConnection, username: String) {
        if (sessionToken?.isNotEmpty() == true) {
            connection.setRequestProperty("X-App-Token", sessionToken)
        }
        if (username.isNotEmpty()) {
            connection.setRequestProperty("X-App-Username", username)
        }
    }

    private fun readResponse(connection: HttpURLConnection): String {
        val stream = if (connection.responseCode in 200..299) connection.inputStream else connection.errorStream
        return stream?.bufferedReader()?.use(BufferedReader::readText) ?: ""
    }

    // Validates password against server API, returns supervisor name if valid, null if invalid
    // Uses fallback passwords if server is unreachable
    private fun validatePassword(password: String, type: String): String? {
        return try {
            val url = URL("${getServerUrl()}/api/app/validate-password")
            val connection = url.openConnection() as HttpURLConnection
            connection.connectTimeout = 5000
            connection.readTimeout = 5000
            connection.requestMethod = "POST"
            connection.setRequestProperty("Content-Type", "application/json")
            connection.doOutput = true

            val json = JSONObject().apply {
                put("password", password)
                put("type", type)
            }
            connection.outputStream.write(json.toString().toByteArray())

            val response = readResponse(connection)
            val jsonResponse = JSONObject(response)

            if (jsonResponse.optBoolean("valid", false)) {
                jsonResponse.optString("name", "Unknown")
            } else {
                null
            }
        } catch (e: Exception) {
            // Server unreachable - use fallback passwords
            if (type == "admin") {
                if (password == FALLBACK_ADMIN_PASSWORD) "Admin" else null
            } else {
                FALLBACK_SUPERVISOR_PASSWORDS[password]
            }
        }
    }

    private fun authenticate(): Boolean {
        val username = etUsername.text.toString().trim()
        if (username.isEmpty()) {
            runOnUiThread {
                Toast.makeText(this, "Enter username to authenticate", Toast.LENGTH_SHORT).show()
            }
            return false
        }

        return try {
            val url = URL("${getServerUrl()}/api/app/authenticate")
            val connection = url.openConnection() as HttpURLConnection
            connection.connectTimeout = 10000
            connection.readTimeout = 10000
            connection.requestMethod = "POST"
            connection.setRequestProperty("Content-Type", "application/json")
            addAppHeaders(connection, username)
            connection.doOutput = true

            val json = JSONObject().apply { put("username", username) }
            connection.outputStream.bufferedWriter().use { it.write(json.toString()) }

            val response = readResponse(connection)
            val result = JSONObject(response)
            val success = result.optBoolean("success", false)

            if (success) {
                val token = result.optString("token", "")
                if (token.isNotEmpty()) {
                    saveSessionToken(token)
                }

                val proxyIndex = result.optInt("proxy_index", -1)
                if (proxyIndex >= 0) {
                    val position = proxyList.indexOfFirst { it.index == proxyIndex }
                    if (position >= 0) {
                        runOnUiThread { spinnerProxy.setSelection(position) }
                    }
                }

                runOnUiThread {
                    tvStatus.text = "Authenticated as $username"
                    tvStatus.setTextColor(getColor(R.color.status_connected))
                }
            } else {
                val message = result.optString("message", "Authentication failed")
                runOnUiThread {
                    tvStatus.text = "Auth error: $message"
                    tvStatus.setTextColor(getColor(R.color.status_disconnected))
                }
            }

            success
        } catch (e: Exception) {
            runOnUiThread {
                tvStatus.text = "Auth error: ${e.message?.take(40)}"
                tvStatus.setTextColor(getColor(R.color.status_disconnected))
            }
            false
        }
    }

    private fun fetchProxies() {
        val serverIp = etServerIp.text.toString().trim()
        val username = etUsername.text.toString().trim()
        if (serverIp.isEmpty()) {
            Toast.makeText(this, "Enter server IP first", Toast.LENGTH_SHORT).show()
            return
        }

        if (username.isEmpty()) {
            Toast.makeText(this, "Enter username first", Toast.LENGTH_SHORT).show()
            return
        }

        tvStatus.text = "Fetching proxies..."
        tvStatus.setTextColor(getColor(R.color.text_secondary))
        btnRefresh.isEnabled = false

        Thread {
            try {
                var attemptedAuth = false
                while (true) {
                    val url = URL("${getServerUrl()}/api/app/proxies")
                    val connection = url.openConnection() as HttpURLConnection
                    connection.connectTimeout = 10000
                    connection.readTimeout = 10000
                    connection.requestMethod = "GET"
                    addAppHeaders(connection, username)

                    val responseCode = connection.responseCode
                    val response = readResponse(connection)

                    if (responseCode == 401 && !attemptedAuth) {
                        attemptedAuth = true
                        if (authenticate()) {
                            continue
                        }
                    }

                    if (responseCode == 200) {
                        val jsonArray = JSONArray(response)

                        proxyList.clear()
                        for (i in 0 until jsonArray.length()) {
                            val obj = jsonArray.getJSONObject(i)
                            proxyList.add(ProxyItem(obj.getInt("index"), obj.getString("name")))
                        }

                        runOnUiThread {
                            btnRefresh.isEnabled = true
                            updateProxySpinner()
                            tvStatus.text = "Found ${proxyList.size} proxies"
                            tvStatus.setTextColor(getColor(R.color.status_connected))
                        }
                    } else {
                        val message = try {
                            JSONObject(response).optString("message", "Server returned $responseCode")
                        } catch (e: Exception) {
                            "Server returned $responseCode"
                        }
                        runOnUiThread {
                            btnRefresh.isEnabled = true
                            tvStatus.text = message
                            tvStatus.setTextColor(getColor(R.color.status_disconnected))
                        }
                    }
                    connection.disconnect()
                    break
                }
            } catch (e: Exception) {
                runOnUiThread {
                    btnRefresh.isEnabled = true
                    tvStatus.text = "Error: ${e.message?.take(40)}"
                    tvStatus.setTextColor(getColor(R.color.status_disconnected))
                }
            }
        }.start()
    }

    private fun updateProxySpinner() {
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, proxyList)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spinnerProxy.adapter = adapter

        // Restore saved selection
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val savedIndex = prefs.getInt(KEY_PROXY_INDEX, 0)
        val position = proxyList.indexOfFirst { it.index == savedIndex }
        if (position >= 0) {
            spinnerProxy.setSelection(position)
        }
    }

    private fun connectDevice() {
        val serverIp = etServerIp.text.toString().trim()
        val username = etUsername.text.toString().trim()

        if (serverIp.isEmpty()) {
            Toast.makeText(this, "Enter server IP", Toast.LENGTH_SHORT).show()
            return
        }
        if (username.isEmpty()) {
            Toast.makeText(this, "Enter username", Toast.LENGTH_SHORT).show()
            return
        }

        saveSettings()
        tvStatus.text = "Connecting..."
        tvStatus.setTextColor(getColor(R.color.text_secondary))
        btnConnect.isEnabled = false

        // Authenticate and check IP
        Thread {
            try {
                val authenticated = authenticate()
                runOnUiThread {
                    btnConnect.isEnabled = true
                    if (authenticated) {
                        tvStatus.text = "Connected as $username"
                        tvStatus.setTextColor(getColor(R.color.status_connected))
                        // Trigger IP check
                        checkWhoAmI()
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    btnConnect.isEnabled = true
                    tvStatus.text = "Error: ${e.message?.take(40)}"
                    tvStatus.setTextColor(getColor(R.color.status_disconnected))
                }
            }
        }.start()
    }

    private fun registerDevice() {
        val serverIp = etServerIp.text.toString().trim()
        val username = etUsername.text.toString().trim()

        if (serverIp.isEmpty()) {
            Toast.makeText(this, "Enter server IP", Toast.LENGTH_SHORT).show()
            return
        }
        if (username.isEmpty()) {
            Toast.makeText(this, "Enter username", Toast.LENGTH_SHORT).show()
            return
        }
        if (proxyList.isEmpty()) {
            Toast.makeText(this, "Fetch proxies first", Toast.LENGTH_SHORT).show()
            return
        }

        val selectedProxy = spinnerProxy.selectedItem as? ProxyItem
        if (selectedProxy == null) {
            Toast.makeText(this, "Select a proxy", Toast.LENGTH_SHORT).show()
            return
        }

        // Show password dialog with rollout option
        showRegistrationPasswordDialog(username, selectedProxy)
    }

    private fun showRegistrationPasswordDialog(username: String, selectedProxy: ProxyItem) {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(50, 30, 50, 10)
        }

        val passwordInput = EditText(this).apply {
            hint = "Enter admin password"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        layout.addView(passwordInput)

        val rolloutCheckbox = CheckBox(this).apply {
            text = "Rollout Setup (lock username & proxy)"
            setPadding(0, 20, 0, 0)
        }
        layout.addView(rolloutCheckbox)

        AlertDialog.Builder(this)
            .setTitle("Admin Registration")
            .setMessage("Enter admin password to register this device")
            .setView(layout)
            .setPositiveButton("Register") { _, _ ->
                val password = passwordInput.text.toString()
                if (password.isEmpty()) {
                    Toast.makeText(this, "Password is required", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                val enableRollout = rolloutCheckbox.isChecked

                // Validate password in background thread
                tvStatus.text = "Validating password..."
                Thread {
                    val adminName = validatePassword(password, "admin")
                    runOnUiThread {
                        if (adminName != null) {
                            performRegistration(username, selectedProxy, password, enableRollout)
                        } else {
                            tvStatus.text = "Ready"
                            Toast.makeText(this, "Invalid admin password", Toast.LENGTH_SHORT).show()
                        }
                    }
                }.start()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun performRegistration(username: String, selectedProxy: ProxyItem, password: String, enableRollout: Boolean) {
        saveSettings()

        tvStatus.text = "Registering..."
        tvStatus.setTextColor(getColor(R.color.text_secondary))
        btnRegister.isEnabled = false

        Thread {
            try {
                var attemptedAuth = false
                while (true) {
                    val url = URL("${getServerUrl()}/api/app/register")
                    val connection = url.openConnection() as HttpURLConnection
                    connection.connectTimeout = 10000
                    connection.readTimeout = 10000
                    connection.requestMethod = "POST"
                    connection.setRequestProperty("Content-Type", "application/json")
                    addAppHeaders(connection, username)
                    connection.doOutput = true

                    val json = JSONObject().apply {
                        put("username", username)
                        put("proxy_index", selectedProxy.index)
                        put("password", password)
                    }

                    connection.outputStream.bufferedWriter().use { it.write(json.toString()) }

                    val responseCode = connection.responseCode
                    val response = readResponse(connection)

                    if (responseCode == 401 && !attemptedAuth) {
                        attemptedAuth = true
                        if (authenticate()) {
                            continue
                        }
                    }

                    val result = JSONObject(response)
                    connection.disconnect()

                    runOnUiThread {
                        btnRegister.isEnabled = true
                        if (result.optBoolean("success", false)) {
                            val proxyName = result.optString("proxy_name", selectedProxy.name)
                            tvStatus.text = "Registered: $username -> $proxyName"
                            tvStatus.setTextColor(getColor(R.color.status_connected))

                            // Save rollout mode if enabled
                            if (enableRollout) {
                                isRolloutMode = true
                                val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                                prefs.edit { putBoolean(KEY_ROLLOUT_MODE, true) }
                                applyRolloutMode()
                                Toast.makeText(this, "Device registered with Rollout Setup!", Toast.LENGTH_LONG).show()
                            } else {
                                Toast.makeText(this, "Device registered!", Toast.LENGTH_SHORT).show()
                            }
                        } else {
                            val message = result.optString("message", "Registration failed")
                            tvStatus.text = "Error: $message"
                            tvStatus.setTextColor(getColor(R.color.status_disconnected))
                        }
                    }
                    break
                }
            } catch (e: Exception) {
                runOnUiThread {
                    btnRegister.isEnabled = true
                    tvStatus.text = "Error: ${e.message?.take(40)}"
                    tvStatus.setTextColor(getColor(R.color.status_disconnected))
                }
            }
        }.start()
    }

    private fun changeProxy() {
        val serverIp = etServerIp.text.toString().trim()
        val username = etUsername.text.toString().trim()

        if (serverIp.isEmpty()) {
            Toast.makeText(this, "Enter server IP", Toast.LENGTH_SHORT).show()
            return
        }
        if (username.isEmpty()) {
            Toast.makeText(this, "Enter username", Toast.LENGTH_SHORT).show()
            return
        }
        if (proxyList.isEmpty()) {
            Toast.makeText(this, "Fetch proxies first", Toast.LENGTH_SHORT).show()
            return
        }

        // Show supervisor password dialog first
        showSupervisorPasswordDialog(username)
    }

    private fun showSupervisorPasswordDialog(username: String) {
        val passwordInput = EditText(this).apply {
            hint = "Enter supervisor password"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            setPadding(50, 30, 50, 30)
        }

        AlertDialog.Builder(this)
            .setTitle("Supervisor Access")
            .setMessage("Enter your supervisor password to change proxy settings")
            .setView(passwordInput)
            .setPositiveButton("Authenticate") { _, _ ->
                val password = passwordInput.text.toString()
                if (password.isEmpty()) {
                    Toast.makeText(this, "Password is required", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }

                // Validate password in background thread
                tvStatus.text = "Validating password..."
                Thread {
                    val supervisorName = validatePassword(password, "supervisor")
                    runOnUiThread {
                        tvStatus.text = if (isRolloutMode) "Rollout Mode - Settings locked" else "Ready"
                        if (supervisorName != null) {
                            // Supervisor authenticated - unlock fields and show proxy selection dialog
                            temporarilyUnlockForSupervisor()
                            Toast.makeText(this, "Welcome, $supervisorName!", Toast.LENGTH_SHORT).show()
                            showProxySelectionDialog(username, supervisorName)
                        } else {
                            Toast.makeText(this, "Invalid supervisor password", Toast.LENGTH_SHORT).show()
                        }
                    }
                }.start()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showProxySelectionDialog(username: String, supervisorName: String) {
        // Create a custom layout with a Spinner for proxy selection
        val layout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(50, 30, 50, 30)
        }

        val infoText = android.widget.TextView(this).apply {
            text = "Supervisor: $supervisorName\nChanging proxy for: $username"
            setPadding(0, 0, 0, 30)
        }
        layout.addView(infoText)

        val proxySpinner = android.widget.Spinner(this)
        val proxyNames = proxyList.map { it.name }
        val adapter = android.widget.ArrayAdapter(this, android.R.layout.simple_spinner_item, proxyNames)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        proxySpinner.adapter = adapter
        proxySpinner.setSelection(spinnerProxy.selectedItemPosition.coerceIn(0, proxyList.size - 1))
        layout.addView(proxySpinner)

        AlertDialog.Builder(this)
            .setTitle("Select New Proxy")
            .setView(layout)
            .setPositiveButton("Change Proxy") { _, _ ->
                val selectedIndex = proxySpinner.selectedItemPosition
                if (selectedIndex >= 0 && selectedIndex < proxyList.size) {
                    val selectedProxy = proxyList[selectedIndex]
                    spinnerProxy.setSelection(selectedIndex)
                    performChangeProxy(username, selectedProxy, supervisorName)
                }
            }
            .setNegativeButton("Cancel") { _, _ ->
                // Re-lock if cancelled
                relockAfterSupervisorChange()
            }
            .setOnCancelListener {
                // Re-lock if dismissed
                relockAfterSupervisorChange()
            }
            .show()
    }

    private fun performChangeProxy(username: String, selectedProxy: ProxyItem, supervisorName: String) {
        saveSettings()

        tvStatus.text = "Updating proxy..."
        tvStatus.setTextColor(getColor(R.color.text_secondary))
        btnChangeProxy.isEnabled = false

        Thread {
            try {
                var attemptedAuth = false
                while (true) {
                    val url = URL("${getServerUrl()}/api/app/change-proxy")
                    val connection = url.openConnection() as HttpURLConnection
                    connection.connectTimeout = 10000
                    connection.readTimeout = 10000
                    connection.requestMethod = "POST"
                    connection.setRequestProperty("Content-Type", "application/json")
                    addAppHeaders(connection, username)
                    connection.doOutput = true

                    val json = JSONObject().apply {
                        put("username", username)
                        put("proxy_index", selectedProxy.index)
                        put("supervisor", supervisorName)  // Send supervisor name for logging
                    }

                    connection.outputStream.bufferedWriter().use { it.write(json.toString()) }

                    val responseCode = connection.responseCode
                    val response = readResponse(connection)

                    if (responseCode == 401 && !attemptedAuth) {
                        attemptedAuth = true
                        if (authenticate()) {
                            continue
                        }
                    }

                    val result = JSONObject(response)
                    connection.disconnect()

                    runOnUiThread {
                        btnChangeProxy.isEnabled = true
                        relockAfterSupervisorChange()  // Re-lock after change
                        if (result.optBoolean("success", false)) {
                            val proxyName = result.optString("proxy_name", selectedProxy.name)
                            tvStatus.text = "Proxy updated by $supervisorName: $username -> $proxyName"
                            tvStatus.setTextColor(getColor(R.color.status_connected))
                            Toast.makeText(this, "Proxy changed by $supervisorName!", Toast.LENGTH_SHORT).show()
                            // Trigger IP check to verify the change
                            checkWhoAmI()
                        } else {
                            val message = result.optString("message", "Update failed")
                            tvStatus.text = "Error: $message"
                            tvStatus.setTextColor(getColor(R.color.status_disconnected))
                        }
                    }
                    break
                }
            } catch (e: Exception) {
                runOnUiThread {
                    btnChangeProxy.isEnabled = true
                    relockAfterSupervisorChange()
                    tvStatus.text = "Error: ${e.message?.take(40)}"
                    tvStatus.setTextColor(getColor(R.color.status_disconnected))
                }
            }
        }.start()
    }

    private fun checkWhoAmI() {
        tvWhoAmI.text = "Checking IP..."
        tvWhoAmI.setTextColor(getColor(R.color.text_secondary))

        // Get selected proxy name for comparison
        val selectedProxy = spinnerProxy.selectedItem as? ProxyItem
        val selectedProxyName = selectedProxy?.name ?: ""

        Thread {
            try {
                val serverIp = etServerIp.text.toString().trim()

                // Get proxy configuration for routing the IP check through the proxy
                val proxyHost = serverIp.ifEmpty { "192.168.50.60" }
                val proxyPort = 8888  // HTTP proxy port

                var publicIP = ""
                var country = ""
                var countryCode = ""
                var city = ""
                var proxyCheckSuccess = false
                var directCheckFallback = false

                // Step 1: Try to get public IP through the proxy (this verifies proxy is working)
                try {
                    val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress(proxyHost, proxyPort))
                    val ipApiUrl = URL("http://ip-api.com/json/?fields=status,query,country,city,countryCode")
                    val ipConnection = ipApiUrl.openConnection(proxy) as HttpURLConnection
                    ipConnection.connectTimeout = 15000
                    ipConnection.readTimeout = 15000
                    ipConnection.requestMethod = "GET"

                    val ipResponse = readResponse(ipConnection)
                    ipConnection.disconnect()

                    val ipResult = JSONObject(ipResponse)
                    if (ipResult.optString("status") == "success") {
                        publicIP = ipResult.optString("query", "?")
                        country = ipResult.optString("country", "")
                        countryCode = ipResult.optString("countryCode", "")
                        city = ipResult.optString("city", "")
                        proxyCheckSuccess = true
                    }
                } catch (e: Exception) {
                    // Proxy connection failed - will try direct connection as fallback
                    proxyCheckSuccess = false
                }

                // Step 2: If proxy check failed, try direct connection (to show user their real IP)
                if (!proxyCheckSuccess) {
                    try {
                        directCheckFallback = true
                        val ipApiUrl = URL("http://ip-api.com/json/?fields=status,query,country,city,countryCode")
                        val ipConnection = ipApiUrl.openConnection() as HttpURLConnection
                        ipConnection.connectTimeout = 15000
                        ipConnection.readTimeout = 15000
                        ipConnection.requestMethod = "GET"

                        val ipResponse = readResponse(ipConnection)
                        ipConnection.disconnect()

                        val ipResult = JSONObject(ipResponse)
                        if (ipResult.optString("status") == "success") {
                            publicIP = ipResult.optString("query", "?")
                            country = ipResult.optString("country", "")
                            countryCode = ipResult.optString("countryCode", "")
                            city = ipResult.optString("city", "")
                        }
                    } catch (e: Exception) {
                        runOnUiThread {
                            tvWhoAmI.text = "Failed to check IP - network error"
                            tvWhoAmI.setTextColor(getColor(R.color.status_disconnected))
                        }
                        return@Thread
                    }
                }

                if (publicIP.isEmpty()) {
                    runOnUiThread {
                        tvWhoAmI.text = "Failed to check IP"
                        tvWhoAmI.setTextColor(getColor(R.color.status_disconnected))
                    }
                    return@Thread
                }

                val location = listOf(city, country).filter { it.isNotEmpty() }.joinToString(", ")

                // Check if country is Singapore
                val isSingapore = countryCode.equals("SG", ignoreCase = true) ||
                        country.equals("Singapore", ignoreCase = true)

                // Step 3: Check with server which proxy this IP belongs to
                var detectedProxy = ""
                var isMatched = false
                var warningMsg = ""

                if (serverIp.isNotEmpty()) {
                    try {
                        val checkUrl = URL("${getServerUrl()}/api/app/check-ip?ip=$publicIP")
                        val checkConnection = checkUrl.openConnection() as HttpURLConnection
                        checkConnection.connectTimeout = 10000
                        checkConnection.readTimeout = 10000
                        checkConnection.requestMethod = "GET"

                        val checkResponse = readResponse(checkConnection)
                        checkConnection.disconnect()

                        val checkResult = JSONObject(checkResponse)
                        isMatched = checkResult.optBoolean("matched", false)
                        if (isMatched) {
                            detectedProxy = checkResult.optString("proxy_name", "")
                        } else {
                            warningMsg = checkResult.optString("message", "IP not in proxy list")
                        }
                    } catch (e: Exception) {
                        // Server check failed, just show IP without proxy info
                    }
                }

                // Store detected proxy for other functions
                detectedProxyName = if (isMatched) detectedProxy else null

                // Build display string
                val displayBuilder = StringBuilder()
                displayBuilder.append(publicIP)
                if (location.isNotEmpty()) {
                    displayBuilder.append(" ($location)")
                }

                runOnUiThread {
                    var hasWarning = false
                    var warningTitle = ""
                    var warningMessage = ""

                    // Check 0: Did proxy connection fail? (had to use direct fallback)
                    if (directCheckFallback) {
                        hasWarning = true
                        displayBuilder.append("\n\n⚠️ PROXY NOT WORKING!")
                        displayBuilder.append("\nShowing your real device IP (not proxied)")
                        warningTitle = "⚠️ Proxy Connection Failed"
                        warningMessage = "Could not connect through the proxy at $proxyHost:$proxyPort.\n\nThe IP shown ($publicIP) is your real device IP, NOT the proxy IP.\n\nPlease:\n1. Check Wi-Fi is connected\n2. Verify Wi-Fi proxy settings (Host: $proxyHost, Port: 8888)\n3. Make sure the proxy server is running\n4. Contact your Supervisor if the issue persists"
                    }

                    // Check 1: Is it from Singapore?
                    if (!isSingapore && !hasWarning) {
                        hasWarning = true
                        displayBuilder.append("\n\n⚠️ WARNING: NOT from Singapore!")
                        displayBuilder.append("\nCountry: $country")
                        warningTitle = "⚠️ Wrong Location"
                        warningMessage = "Your IP address ($publicIP) is from $country, NOT from Singapore!\n\nPlease:\n1. Check your Wi-Fi proxy settings\n2. Make sure you're connected through the correct proxy\n3. Contact your Supervisor immediately"
                    }

                    // Check 2: Is it a recognized proxy?
                    if (isMatched && !directCheckFallback) {
                        displayBuilder.append("\n✓ $detectedProxy")

                        // Check if detected proxy matches selected proxy
                        if (selectedProxyName.isNotEmpty() && detectedProxy != selectedProxyName) {
                            hasWarning = true
                            displayBuilder.append("\n\n⚠️ MISMATCH: Selected $selectedProxyName but connected via $detectedProxy")
                            warningTitle = "⚠️ Proxy Mismatch"
                            warningMessage = "Your selected proxy is $selectedProxyName but you're connected via $detectedProxy.\n\nPlease:\n1. Check your Wi-Fi proxy settings\n2. Make sure you're on the correct network\n3. Contact your Supervisor if the issue persists"
                        }
                    } else if (warningMsg.isNotEmpty() && !directCheckFallback) {
                        hasWarning = true
                        displayBuilder.append("\n\n⚠️ $warningMsg")
                        if (warningTitle.isEmpty()) {
                            warningTitle = "⚠️ Unknown IP"
                            warningMessage = "Your IP address ($publicIP) is not recognized as one of our proxies.\n\nPlease:\n1. Check your Wi-Fi proxy settings\n2. Make sure you're connected through the proxy\n3. Contact your Supervisor if the issue persists"
                        }
                    }

                    if (hasWarning) {
                        displayBuilder.append("\n\nPlease check Wi-Fi settings or contact Supervisor!")
                        tvWhoAmI.text = displayBuilder.toString()
                        tvWhoAmI.setTextColor(getColor(R.color.status_disconnected))

                        // Show alert dialog
                        if (warningTitle.isNotEmpty()) {
                            AlertDialog.Builder(this)
                                .setTitle(warningTitle)
                                .setMessage(warningMessage)
                                .setPositiveButton("OK", null)
                                .show()
                        }
                    } else {
                        // All good - matched and from Singapore
                        displayBuilder.append("\n✓ Session confirmed")
                        tvWhoAmI.text = displayBuilder.toString()
                        tvWhoAmI.setTextColor(getColor(R.color.status_connected))

                        // Confirm session with server
                        confirmConnection()
                    }
                }

            } catch (e: Exception) {
                runOnUiThread {
                    tvWhoAmI.text = "Error: ${e.message?.take(40)}"
                    tvWhoAmI.setTextColor(getColor(R.color.status_disconnected))
                }
            }
        }.start()
    }

    private fun confirmConnection() {
        val serverIp = etServerIp.text.toString().trim()
        val username = etUsername.text.toString().trim()

        if (serverIp.isEmpty() || username.isEmpty()) {
            return  // Can't confirm without server/username
        }

        Thread {
            try {
                val url = URL("${getServerUrl()}/api/app/confirm-connection")
                val connection = url.openConnection() as HttpURLConnection
                connection.connectTimeout = 10000
                connection.readTimeout = 10000
                connection.requestMethod = "POST"
                connection.setRequestProperty("Content-Type", "application/json")
                addAppHeaders(connection, username)
                connection.doOutput = true

                val json = JSONObject().apply {
                    put("username", username)
                }
                connection.outputStream.bufferedWriter().use { it.write(json.toString()) }

                val responseCode = connection.responseCode
                val response = readResponse(connection)
                connection.disconnect()

                if (responseCode == 200) {
                    val result = JSONObject(response)
                    if (result.optBoolean("confirmed", false)) {
                        val timeout = result.optInt("timeout_hours", 2)
                        runOnUiThread {
                            tvStatus.text = "Session confirmed (valid for ${timeout}h)"
                            tvStatus.setTextColor(getColor(R.color.status_connected))
                        }
                    }
                }
            } catch (e: Exception) {
                // Silently fail - session confirmation is best-effort
            }
        }.start()
    }

    // Auto-check IP when app resumes
    override fun onResume() {
        super.onResume()
        // Sync settings from server and then check IP
        syncSettingsFromServer()
    }

    // Sync device settings from the server (in case they were changed from dashboard)
    private fun syncSettingsFromServer() {
        val serverIp = etServerIp.text.toString().trim()
        val username = etUsername.text.toString().trim()

        if (serverIp.isEmpty() || username.isEmpty()) {
            // No server/username configured, just check IP
            tvWhoAmI.postDelayed({ checkWhoAmI() }, 500)
            return
        }

        Thread {
            try {
                // First fetch proxies if list is empty
                if (proxyList.isEmpty()) {
                    try {
                        val proxiesUrl = URL("${getServerUrl()}/api/app/proxies")
                        val proxiesConn = proxiesUrl.openConnection() as HttpURLConnection
                        proxiesConn.connectTimeout = 10000
                        proxiesConn.readTimeout = 10000
                        proxiesConn.requestMethod = "GET"
                        addAppHeaders(proxiesConn, username)

                        if (proxiesConn.responseCode == 200) {
                            val proxiesResponse = readResponse(proxiesConn)
                            val jsonArray = JSONArray(proxiesResponse)
                            proxyList.clear()
                            for (i in 0 until jsonArray.length()) {
                                val obj = jsonArray.getJSONObject(i)
                                proxyList.add(ProxyItem(obj.getInt("index"), obj.getString("name")))
                            }
                            runOnUiThread { updateProxySpinner() }
                        }
                        proxiesConn.disconnect()
                    } catch (e: Exception) {
                        // Ignore proxy fetch errors
                    }
                }

                // Now fetch device settings
                val url = URL("${getServerUrl()}/api/app/device-settings?username=$username")
                val connection = url.openConnection() as HttpURLConnection
                connection.connectTimeout = 10000
                connection.readTimeout = 10000
                connection.requestMethod = "GET"
                addAppHeaders(connection, username)

                val responseCode = connection.responseCode
                val response = readResponse(connection)
                connection.disconnect()

                if (responseCode == 200) {
                    val result = JSONObject(response)
                    if (result.optBoolean("success", false)) {
                        val serverProxyIndex = result.optInt("proxy_index", -1)
                        val serverProxyName = result.optString("proxy_name", "")
                        val sessionValid = result.optBoolean("session_valid", false)
                        val sessionTimeout = result.optInt("session_timeout", 2)

                        runOnUiThread {
                            // Update proxy selection if it differs from server
                            if (serverProxyIndex >= 0 && proxyList.isNotEmpty()) {
                                val currentSelection = (spinnerProxy.selectedItem as? ProxyItem)?.index ?: -1
                                if (currentSelection != serverProxyIndex) {
                                    val position = proxyList.indexOfFirst { it.index == serverProxyIndex }
                                    if (position >= 0) {
                                        spinnerProxy.setSelection(position)
                                        // Save the updated selection
                                        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                                        prefs.edit { putInt(KEY_PROXY_INDEX, serverProxyIndex) }
                                        Toast.makeText(this, "Proxy updated to: $serverProxyName", Toast.LENGTH_SHORT).show()
                                    }
                                }
                            }

                            // Update status based on session validity
                            if (sessionValid) {
                                tvStatus.text = "Session active (${sessionTimeout}h timeout)"
                                tvStatus.setTextColor(getColor(R.color.status_connected))
                            } else {
                                tvStatus.text = "Session expired - tap Connect"
                                tvStatus.setTextColor(getColor(R.color.status_disconnected))
                            }

                            // Now check IP
                            checkWhoAmI()
                        }
                    } else {
                        // Device not registered or other error
                        runOnUiThread {
                            checkWhoAmI()
                        }
                    }
                } else {
                    runOnUiThread {
                        checkWhoAmI()
                    }
                }
            } catch (e: Exception) {
                // Server unreachable, just check IP
                runOnUiThread {
                    tvWhoAmI.postDelayed({ checkWhoAmI() }, 500)
                }
            }
        }.start()
    }
}
