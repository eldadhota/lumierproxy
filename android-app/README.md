# Lumier Proxy Connect - Android App

A simple Android app that connects to the Lumier Dynamics proxy management system with automatic device identification via username.

## Features

- Connect to your Lumier proxy server using a unique username
- Automatic device identification even when IP changes
- VPN-based traffic routing through the proxy
- Persistent settings - enter your config once

## How to Build

### Prerequisites

- Android Studio Arctic Fox or newer
- JDK 17+
- Android SDK with API level 34

### Building

1. Open this `android-app` folder in Android Studio
2. Wait for Gradle sync to complete
3. Build > Build Bundle(s) / APK(s) > Build APK(s)
4. The APK will be in `app/build/outputs/apk/debug/`

### Or build from command line:

```bash
cd android-app
./gradlew assembleDebug
```

## Usage

1. Install the APK on your Android device
2. Enter your Lumier proxy server IP address (e.g., `192.168.1.100`)
3. Enter the server port (default: `8080`)
4. Enter a unique username for this device (e.g., `johns-phone`, `samsung-s23`)
5. Tap **Connect**
6. Grant VPN permission when prompted

The app will:
- Create a VPN tunnel that routes traffic through your proxy server
- Authenticate with your username so the server knows which device is connecting
- Maintain your device identity even if your IP address changes

## How It Works

The app uses Android's VPN API to capture network traffic and route it through your Lumier proxy server. Your username is sent in the `Proxy-Authorization` header (Basic auth format) with each request, allowing the server to identify your device regardless of IP changes.

## Server Requirements

Your Lumier proxy server (the Go application) must be running and accessible from the Android device's network. The proxy server will automatically:

- Register new devices when they first connect
- Associate the username with the device
- Maintain device history and settings
- Assign configured upstream proxies to the device

## Troubleshooting

**Can't connect:**
- Verify the server IP and port are correct
- Ensure the Android device can reach the server network
- Check that the Lumier proxy server is running

**Connection drops:**
- The app maintains a persistent VPN connection
- If disconnected, simply tap Connect again
- Your settings are saved locally

**Username not showing on dashboard:**
- Make sure you're entering a non-empty username
- The username appears after the first request is made through the proxy

## License

Part of the Lumier Dynamics proxy management system.
