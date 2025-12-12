# lumierproxy

## Troubleshooting Windows connectivity to proxies

If `Test-NetConnection <proxy-ip> -Port <port>` hangs at "Attempting TCP connect" / "Waiting for response" on Windows 11, it means the server cannot open a TCP socket to that host:port. Check these next steps:

- Confirm the proxy is listening and reachable from the server network (firewall or NAT may block the port).
- Try `Test-NetConnection <proxy-ip> -Port <port> -InformationLevel Detailed` to see DNS and routing results.
- Use `curl -v -x socks5://user:pass@<proxy-ip>:<port> https://example.com/` from the same machine. If it times out or cannot connect, the upstream proxy or route is unreachable.
- If the IP is on a local subnet (e.g., 192.168.x.x), ensure the server has a route to that network and that Windows Defender Firewall allows outbound traffic on that port.

A successful test shows `TcpTestSucceeded : True`. Any hang or failure indicates a network path, firewall, or proxy availability issue rather than a formatting problem in `proxies.txt`.

## Connecting from the Android app after connectivity tests succeed

Once `Test-NetConnection` succeeds on your server, configure the Android device to send traffic through the proxy listener on port **8888** (the dashboard stays on **8080**):

1. Make sure the phone can reach the server's IP (same Wi-Fi/LAN or port-forwarded from the internet). Test in Chrome on the phone: `http://<server-ip>:8080` should load the dashboard login page; if it does not, follow the dashboard reachability steps in the section below.
2. On the phone's Wi-Fi network settings, set **Proxy** to **Manual** with:
   - **Host name:** `<server-ip>`
   - **Port:** `8888`
   - **Type:** HTTP (Android forwards both HTTP/HTTPS through it)
3. Open the Lumier Android app and tap **Refresh proxies**. It should now connect through the server on 8888 to reach your upstream SOCKS5 proxies.
   - The app API endpoints also respond on the proxy listener (8888) so even if the dashboard port is blocked, the **Refresh proxies** / **Register** buttons can still reach the server without timing out.
   - When you register a username and proxy, the server saves that pairing by **username**. Devices that reconnect with the same username keep the same profile/proxy even if their IP changes. IP-only fallback is disabled by default; set `ALLOW_IP_FALLBACK=true` if you want the old behavior of matching by IP when no username is sent.
   - Use the new **Change Proxy** button in the Android app (or `POST /api/app/change-proxy` with `username` and `proxy_index`) to switch a device to another upstream proxy without deleting/re-registering it.

If the app still fails, verify that:
- Windows Defender Firewall (or any upstream firewall/router) allows inbound TCP on port 8888 to the Go server.
- The server is still running and listening on 8888 (`netstat -ano | findstr 8888`).
- Your `proxies.txt` entries are reachable from the server (use the earlier `curl -v -x socks5://...` check).

## If the dashboard at `http://<server-ip>:8080` is unreachable

1. Confirm the server is listening on port 8080:
   - On Windows: `netstat -ano | findstr 8080`
   - On Linux/macOS: `ss -tlnp | grep :8080`
2. Make sure the process is bound to the correct interface. If it shows `127.0.0.1:8080`, only localhost can reach it. Start the server so it binds to `0.0.0.0:8080` or the LAN IP. You can force the listener to bind to the LAN with environment variables:
   - `BIND_ADDR=0.0.0.0` (default) binds to all IPv4 interfaces.
   - `DASHBOARD_PORT=<port>` and `PROXY_PORT=<port>` override the default 8080/8888 ports if those are blocked.
3. Allow inbound TCP 8080 through the OS firewall (e.g., Windows Defender Firewall rule, `ufw allow 8080/tcp` on Ubuntu).
4. If the host PC can reach `http://<server-ip>:8080` but another device on the same Wi‑Fi cannot:
   - The server is likely bound to the wrong interface or blocked by the firewall. Re-run the listener so it binds to `0.0.0.0:8080` and add an inbound firewall rule scoped to **Private** networks in Windows (or your LAN subnet).
   - Verify both devices are on the same LAN/subnet and not isolated by the router/AP (guest Wi‑Fi often blocks client-to-client traffic). If isolation is enabled, move both devices to the same non-guest network or disable isolation.
   - If using a VPN on the server, ensure 8080 is allowed on the VPN adapter or test with the VPN disconnected to confirm LAN reachability.
5. Verify you are using the server’s LAN IP that other devices can reach (e.g., `192.168.1.14` on the same Wi‑Fi). If you’re on a different network, port-forward 8080 on your router to the server.
6. From another device on the same network, test with `curl http://<server-ip>:8080/` or a browser. If it fails, recheck firewall/routing; if it works locally but not externally, it’s a network reachability issue, not the app.
