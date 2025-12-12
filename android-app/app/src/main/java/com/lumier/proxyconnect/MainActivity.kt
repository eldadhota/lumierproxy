package com.lumier.proxyconnect

import android.content.Context
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
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
    }

    private lateinit var etServerIp: EditText
    private lateinit var etServerPort: EditText
    private lateinit var etUsername: EditText
    private lateinit var spinnerProxy: Spinner
    private lateinit var btnRefresh: Button
    private lateinit var btnRegister: Button
    private lateinit var btnChangeProxy: Button
    private lateinit var btnCheckIp: Button
    private lateinit var tvStatus: TextView
    private lateinit var tvWhoAmI: TextView

    private val proxyList = mutableListOf<ProxyItem>()
    private var sessionToken: String? = null

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
        btnRegister = findViewById(R.id.btnRegister)
        btnChangeProxy = findViewById(R.id.btnChangeProxy)
        btnCheckIp = findViewById(R.id.btnCheckIp)
        tvStatus = findViewById(R.id.tvStatus)
        tvWhoAmI = findViewById(R.id.tvWhoAmI)

        loadSavedSettings()

        btnRefresh.setOnClickListener { fetchProxies() }
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
                            Toast.makeText(this, "Device registered!", Toast.LENGTH_SHORT).show()
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

        tvWhoAmI.text = "Checking..."
        Thread {
            try {
                var attemptedAuth = false
                while (true) {
                    val url = URL("${getServerUrl()}/api/app/whoami")
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
                        val result = JSONObject(response)
                        val ip = result.optString("ip", "?")
                        val country = result.optString("country", "")
                        val display = if (country.isNotEmpty()) "$ip ($country)" else ip
                        runOnUiThread { tvWhoAmI.text = display }
                    } else {
                        val message = try {
                            JSONObject(response).optString("message", "Error $responseCode")
                        } catch (e: Exception) {
                            "Error $responseCode"
                        }
                        runOnUiThread { tvWhoAmI.text = message }
                    }
                    connection.disconnect()
                    break
                }
            } catch (e: Exception) {
                runOnUiThread { tvWhoAmI.text = "Error: ${e.message?.take(30)}" }
            }
        }.start()
    }
}
