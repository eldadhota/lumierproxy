package com.lumier.proxyconnect

import android.content.Context
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

        // Passwords
        const val ADMIN_PASSWORD = "Drnda123"
        const val SUPERVISOR_PASSWORD = "DobroJeMirko321a"
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

        // Auto-fetch proxies if server is configured
        if (etServerIp.text.isNotEmpty()) {
            fetchProxies()
        }
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
            // Lock username and proxy selection in rollout mode
            etUsername.isEnabled = false
            spinnerProxy.isEnabled = false
            btnRefresh.visibility = View.GONE
            tvStatus.text = "Rollout Mode - Settings locked"
            tvStatus.setTextColor(getColor(R.color.primary))
        } else {
            etUsername.isEnabled = true
            spinnerProxy.isEnabled = true
            btnRefresh.visibility = View.VISIBLE
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
                if (password != ADMIN_PASSWORD) {
                    Toast.makeText(this, "Invalid admin password", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                val enableRollout = rolloutCheckbox.isChecked
                performRegistration(username, selectedProxy, password, enableRollout)
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

        val selectedProxy = spinnerProxy.selectedItem as? ProxyItem
        if (selectedProxy == null) {
            Toast.makeText(this, "Select a proxy", Toast.LENGTH_SHORT).show()
            return
        }

        // Show supervisor password dialog
        showSupervisorPasswordDialog(username, selectedProxy)
    }

    private fun showSupervisorPasswordDialog(username: String, selectedProxy: ProxyItem) {
        val passwordInput = EditText(this).apply {
            hint = "Enter supervisor password"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            setPadding(50, 30, 50, 30)
        }

        AlertDialog.Builder(this)
            .setTitle("Supervisor Access")
            .setMessage("Enter supervisor password to change proxy")
            .setView(passwordInput)
            .setPositiveButton("Change Proxy") { _, _ ->
                val password = passwordInput.text.toString()
                if (password.isEmpty()) {
                    Toast.makeText(this, "Password is required", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                if (password != SUPERVISOR_PASSWORD) {
                    Toast.makeText(this, "Invalid supervisor password", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                performChangeProxy(username, selectedProxy)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun performChangeProxy(username: String, selectedProxy: ProxyItem) {
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
                        if (result.optBoolean("success", false)) {
                            val proxyName = result.optString("proxy_name", selectedProxy.name)
                            tvStatus.text = "Proxy updated: $username -> $proxyName"
                            tvStatus.setTextColor(getColor(R.color.status_connected))
                            Toast.makeText(this, "Proxy changed!", Toast.LENGTH_SHORT).show()
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
                // Step 1: Get public IP directly from external service (device's actual IP)
                val ipApiUrl = URL("http://ip-api.com/json/?fields=status,query,country,city")
                val ipConnection = ipApiUrl.openConnection() as HttpURLConnection
                ipConnection.connectTimeout = 15000
                ipConnection.readTimeout = 15000
                ipConnection.requestMethod = "GET"

                val ipResponse = readResponse(ipConnection)
                ipConnection.disconnect()

                val ipResult = JSONObject(ipResponse)
                if (ipResult.optString("status") != "success") {
                    runOnUiThread {
                        tvWhoAmI.text = "Failed to check IP"
                        tvWhoAmI.setTextColor(getColor(R.color.status_disconnected))
                    }
                    return@Thread
                }

                val publicIP = ipResult.optString("query", "?")
                val country = ipResult.optString("country", "")
                val city = ipResult.optString("city", "")
                val location = listOf(city, country).filter { it.isNotEmpty() }.joinToString(", ")

                // Step 2: Check with server which proxy this IP belongs to
                val serverIp = etServerIp.text.toString().trim()
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
                    if (isMatched) {
                        displayBuilder.append("\n✓ $detectedProxy")

                        // Check if detected proxy matches selected proxy
                        if (selectedProxyName.isNotEmpty() && detectedProxy != selectedProxyName) {
                            // MISMATCH - Show warning
                            displayBuilder.append("\n\n⚠️ MISMATCH: Selected $selectedProxyName but connected via $detectedProxy")
                            displayBuilder.append("\n\nPlease check Wi-Fi settings or contact Supervisor!")
                            tvWhoAmI.text = displayBuilder.toString()
                            tvWhoAmI.setTextColor(getColor(R.color.status_disconnected))

                            // Show alert dialog for mismatch
                            AlertDialog.Builder(this)
                                .setTitle("⚠️ Proxy Mismatch")
                                .setMessage("Your selected proxy is $selectedProxyName but you're connected via $detectedProxy.\n\nPlease:\n1. Check your Wi-Fi proxy settings\n2. Make sure you're on the correct network\n3. Contact your Supervisor if the issue persists")
                                .setPositiveButton("OK", null)
                                .show()
                        } else {
                            // Match - all good
                            tvWhoAmI.text = displayBuilder.toString()
                            tvWhoAmI.setTextColor(getColor(R.color.status_connected))
                        }
                    } else if (warningMsg.isNotEmpty()) {
                        displayBuilder.append("\n\n⚠️ $warningMsg")
                        displayBuilder.append("\n\nPlease check Wi-Fi settings or contact Supervisor!")
                        tvWhoAmI.text = displayBuilder.toString()
                        tvWhoAmI.setTextColor(getColor(R.color.status_disconnected))

                        // Show alert for unrecognized IP
                        AlertDialog.Builder(this)
                            .setTitle("⚠️ Unknown IP")
                            .setMessage("Your IP address ($publicIP) is not recognized as one of our proxies.\n\nPlease:\n1. Check your Wi-Fi proxy settings\n2. Make sure you're connected through the proxy\n3. Contact your Supervisor if the issue persists")
                            .setPositiveButton("OK", null)
                            .show()
                    } else {
                        tvWhoAmI.text = displayBuilder.toString()
                        tvWhoAmI.setTextColor(getColor(R.color.text_secondary))
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

    // Auto-check IP when app resumes
    override fun onResume() {
        super.onResume()
        // Auto-check IP after a short delay to let UI settle
        tvWhoAmI.postDelayed({ checkWhoAmI() }, 500)
    }
}
