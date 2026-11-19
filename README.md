# IDLVPN Multi-Protocol Tunneling Autoscript

Autoscript instalasi otomatis untuk infrastruktur server tunneling **IDLVPN** berbasis **Ubuntu 22.04 LTS** dan **Debian 11/12**.

## Protokol & Layanan
- **SSH & OpenVPN:** OpenSSH, Dropbear, WebSocket (TLS & Non-TLS), BadVPN UDPGW
- **Xray Core:** VMess, VLESS, Trojan (WS / gRPC / TLS)
- **Reverse Proxy:** Nginx & HAProxy (Port 80 & 443 Multi-Routing)
- **DNS Tunneling:** SlowDNS (DNSTT Server)

## Cara Instalasi
```bash
apt update -y && apt install -y wget curl ca-certificates && wget -q -O setup.sh https://raw.githubusercontent.com/imam022/autoscript-idlvpn/main/setup.sh && chmod +x setup.sh && ./setup.sh
```

---
*Copyright &copy; 2026 IDLVPN. All rights reserved.*
