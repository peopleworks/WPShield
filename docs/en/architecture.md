# Architecture

WPShield is designed as a layered system:

1. **Abstractions** define stable contracts.
2. **Core** resolves sites and evaluates rules.
3. **Rule packs** contain platform-specific detection logic.
4. **Gateway/proxy** will inspect bounded request data before forwarding traffic to IIS.
5. **Management UI** will expose configuration and privacy-safe operational evidence.

One WPShield instance may protect multiple IIS-hosted WordPress sites. The HTTP `Host` value selects an explicit site configuration and destination. Unknown hosts must be rejected by the future gateway rather than forwarded to a default site.

The initial deployment mode is `Monitor`. A finding that exceeds the block threshold is recorded as `Observe` until the operator explicitly enables `Block` for that site.
