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
    }

    private lateinit var etServerIp: EditText
    private lateinit var etServerPort: EditText
    private lateinit var etUsername: EditText
    private lateinit var spinnerProxy: Spinner
    private lateinit var btnRefresh: Button
    private lateinit var btnRegister: Button
    private lateinit var tvStatus: TextView

    private val proxyList = mutableListOf<ProxyItem>()

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
        tvStatus = findViewById(R.id.tvStatus)

        loadSavedSettings()

        btnRefresh.setOnClickListener { fetchProxies() }
        btnRegister.setOnClickListener { registerDevice() }

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
    }

    private fun saveSettings() {
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit {
            putString(KEY_SERVER_IP, etServerIp.text.toString().trim())
            putString(KEY_SERVER_PORT, etServerPort.text.toString().trim())
            putString(KEY_USERNAME, etUsername.text.toString().trim())
            putInt(KEY_PROXY_INDEX, (spinnerProxy.selectedItem as? ProxyItem)?.index ?: 0)
        }
    }

    private fun getServerUrl(): String {
        val ip = etServerIp.text.toString().trim()
        val port = etServerPort.text.toString().trim().ifEmpty { "8081" }
        return "http://$ip:$port"
    }

    private fun fetchProxies() {
        val serverIp = etServerIp.text.toString().trim()
        if (serverIp.isEmpty()) {
            Toast.makeText(this, "Enter server IP first", Toast.LENGTH_SHORT).show()
            return
        }

        tvStatus.text = "Fetching proxies..."
        tvStatus.setTextColor(getColor(R.color.text_secondary))
        btnRefresh.isEnabled = false

        Thread {
            try {
                val url = URL("${getServerUrl()}/api/app/proxies")
                val connection = url.openConnection() as HttpURLConnection
                connection.connectTimeout = 10000
                connection.readTimeout = 10000
                connection.requestMethod = "GET"

                val responseCode = connection.responseCode
                if (responseCode == 200) {
                    val response = connection.inputStream.bufferedReader().use(BufferedReader::readText)
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
                    throw Exception("Server returned $responseCode")
                }
                connection.disconnect()
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
                val url = URL("${getServerUrl()}/api/app/register")
                val connection = url.openConnection() as HttpURLConnection
                connection.connectTimeout = 10000
                connection.readTimeout = 10000
                connection.requestMethod = "POST"
                connection.setRequestProperty("Content-Type", "application/json")
                connection.doOutput = true

                val json = JSONObject().apply {
                    put("username", username)
                    put("proxy_index", selectedProxy.index)
                }

                connection.outputStream.bufferedWriter().use { it.write(json.toString()) }

                val responseCode = connection.responseCode
                val response = connection.inputStream.bufferedReader().use(BufferedReader::readText)
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
            } catch (e: Exception) {
                runOnUiThread {
                    btnRegister.isEnabled = true
                    tvStatus.text = "Error: ${e.message?.take(40)}"
                    tvStatus.setTextColor(getColor(R.color.status_disconnected))
                }
            }
        }.start()
    }
}
