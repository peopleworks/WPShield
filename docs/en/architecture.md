# Architecture

WPShield is designed as a layered system:

1. **Abstractions** define stable contracts.
2. **Core** resolves sites and evaluates rules.
3. **Rule packs** contain platform-specific detection logic.
4. **Gateway/proxy** inspects bounded request data before forwarding traffic to IIS. Since M2 this is real rather than intended: a `multipart/form-data` body is buffered in memory within the request limit — never to disk — reduced to a bounded name and a bounded leading sample per file, evaluated by every rule, and then forwarded or refused. See [bounded multipart inspection](m2-multipart-inspection.md) for what is and is not covered.
5. **Management UI** will expose configuration and privacy-safe operational evidence.

One WPShield instance may protect multiple IIS-hosted WordPress sites. The HTTP `Host` value selects an explicit site configuration and destination. An unknown host is rejected with HTTP 421 before any backend is contacted; there is no default site to fall back to.

The initial deployment mode is `Monitor`. A finding that exceeds the block threshold is recorded as `Observe` until the operator explicitly enables `Block` for that site.
