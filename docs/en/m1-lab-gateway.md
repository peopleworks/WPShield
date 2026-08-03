# M1: Multi-site laboratory HTTP gateway

This version listens only on `127.0.0.1:10000`. It must not be exposed to the Internet or replace IIS public bindings yet.

Expected lab topology:

- WPShield Gateway: `127.0.0.1:10000`
- IIS / peopleworks.com.do: `127.0.0.1:8081`
- IIS / peopleworksgpt.com: `127.0.0.1:8082`

Keep the existing public ports 80 and 443 unchanged. Add and verify separate temporary loopback HTTP bindings for the two IIS sites before running the gateway.
