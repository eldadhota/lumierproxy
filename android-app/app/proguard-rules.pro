# Add project specific ProGuard rules here.
# By default, the flags in this file are appended to flags specified
# in /sdk/tools/proguard/proguard-android.txt

# Keep VPN service
-keep class com.lumier.proxyconnect.ProxyVpnService { *; }
