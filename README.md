# Secure Tunnel VPN — IUT Course Project

A from-scratch client/server VPN in pure Python (no third-party VPN tools),
implementing all requirements of the course document, Phases 1 & 2.

## Topology

- Client VM (Linux): TUN interface + encrypted TCP tunnel
- Server VM (Linux): gateway (kernel NAT), AAA, QoS, monitoring, web panels
- Target VM (Linux): destination (nginx) used for acceptance tests

## Phase 1 features

- Raw TCP transport with length-prefix framing (doc 3.1 / 3.3)
- AES-256-GCM end-to-end encryption, random nonce per message (doc 3.2)
- TUN interfaces on both ends; OS treats them as real NICs (doc 4.4)
- Kernel ip_forward + iptables MASQUERADE: destination sees ONLY server IP
- Port mapping table + online-client monitoring (doc 4.1 / 4.2)
- Firewall-bypass acceptance test passed (doc 5)

## Phase 2 features

- SQLite AAA: AUTH_REQ/AUTH_RESP handshake before any data; authorization
  (active / banned / quota); per-session accounting (doc 2)
- Token-bucket rate limiting in user space; quota enforcement with instant
  disconnect + status flip to quota_exhausted (doc 3)
- Traffic monitoring BEFORE NAT with domain extraction from DNS questions,
  HTTP Host headers and TLS SNI (doc 4.1)
- Admin panel (Flask :8000): users & usage, live sessions, Kick, traffic log,
  firewall rule management (doc 4 / 6)
- User portal (Flask :8001): cookie sessions (24h / 30d remember-me),
  account status & quota view, simulated purchase applied to the LIVE
  session without reconnect (doc 5)
- User-space firewall: drop/accept by dst IP / port / domain, global or
  per-client, applied on decrypted packets before forwarding, logged (doc 6)

## Accounts (seeded)

| user       | password       | note        |
| ---------- | -------------- | ----------- |
| alice      | alice-pass-123 | normal user |
| banned_bob | bob-pass-123   | banned      |
| admin      | admin123       | admin panel |

## Run

Server VM:
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j MASQUERADE
sudo python3 -m server.server_main
Client VM:
sudo python3 -m client.client_main --server <SERVER_IP> --user alice --password alice-pass-123
sudo ip route add <TARGET_IP>/32 dev tun0

## Layout

    common/    framing, crypto (AES-GCM), TUN, port mapping, rate limiter
    client/    client_main
    server/    server_main, database (SQLite), traffic_monitor, firewall,
               admin_panel, user_portal
