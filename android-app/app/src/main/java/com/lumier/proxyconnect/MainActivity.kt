package com.lumier.proxyconnect

import android.content.Context
import android.os.Bundle
import android.util.Base64
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.edit
import java.net.HttpURLConnection
import java.net.URL

class MainActivity : AppCompatActivity() {

    companion object {
        const val PREFS_NAME = "LumierProxyPrefs"
        const val KEY_USERNAME = "username"
    }

    private lateinit var etUsername: EditText
    private lateinit var btnRegister: Button
    private lateinit var tvStatus: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        etUsername = findViewById(R.id.etUsername)
        btnRegister = findViewById(R.id.btnRegister)
        tvStatus = findViewById(R.id.tvStatus)

        // Load saved username
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        etUsername.setText(prefs.getString(KEY_USERNAME, ""))

        btnRegister.setOnClickListener {
            val username = etUsername.text.toString().trim()
            if (username.isEmpty()) {
                Toast.makeText(this, "Please enter a username", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            // Save username
            prefs.edit { putString(KEY_USERNAME, username) }

            // Register with proxy
            registerDevice(username)
        }
    }

    private fun registerDevice(username: String) {
        tvStatus.text = "Registering..."
        tvStatus.setTextColor(getColor(R.color.text_secondary))
        btnRegister.isEnabled = false

        Thread {
            try {
                // Make request - proxy configured in Wi-Fi settings will intercept this
                val url = URL("http://httpbin.org/get")
                val connection = url.openConnection() as HttpURLConnection
                connection.connectTimeout = 15000
                connection.readTimeout = 15000
                connection.requestMethod = "GET"

                // Add proxy auth header with username (this is what your server reads)
                val credentials = "$username:"
                val encoded = Base64.encodeToString(credentials.toByteArray(), Base64.NO_WRAP)
                connection.setRequestProperty("Proxy-Authorization", "Basic $encoded")

                val responseCode = connection.responseCode
                connection.disconnect()

                runOnUiThread {
                    btnRegister.isEnabled = true
                    tvStatus.text = "Registered as: $username"
                    tvStatus.setTextColor(getColor(R.color.status_connected))
                    Toast.makeText(this, "Device registered!", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                runOnUiThread {
                    btnRegister.isEnabled = true
                    tvStatus.text = "Error: ${e.message?.take(50)}"
                    tvStatus.setTextColor(getColor(R.color.status_disconnected))
                    Toast.makeText(this, "Check Wi-Fi proxy settings", Toast.LENGTH_LONG).show()
                }
            }
        }.start()
    }
}
