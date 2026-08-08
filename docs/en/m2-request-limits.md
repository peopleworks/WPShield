# M2.1: Bounded request controls

M2.1 adds absolute request-body safety controls before multipart parsing is introduced. The gateway remains loopback-only and `Monitor` remains the default protection mode.

## Defaults

| Setting | Default | Allowed range |
| --- | ---: | ---: |
| `Gateway:MaximumRequestBytes` | 6 MiB (`6291456`) | 1 byte to 64 MiB |
| Transport ceiling | 64 MiB | Fixed |
| Forwarding activity timeout | 100 seconds | 1 to 300 seconds |

The 6 MiB request limit leaves envelope space around the planned 5 MiB legitimate upload limit. The fixed 64 MiB ceiling prevents configuration from removing the safety boundary.

## Behavior

- A known-site request with `Content-Length` above the configured limit is rejected before contacting its backend.
- Requests without a declared length, including chunked bodies, are counted while YARP reads and forwards them.
- A streamed body that crosses the limit stops forwarding and receives a privacy-safe HTTP 413 response when response headers have not started.
- The limit applies in `Monitor`, `Block`, and `Disabled` modes because it is an absolute resource-safety control.
- Unknown hosts still fail closed with HTTP 421 before their bodies are forwarded.
- Responses and logs contain request IDs, site IDs, sizes, and limits only. They do not contain request bodies, full query strings, authorization values, cookies, nonces, or tokens.
- WPShield does not buffer complete bodies in memory and does not write request bodies to disk.

The HTTP 413 response is:

```json
{
  "error": "request_too_large",
  "requestId": "correlation-id"
}
```

## Streaming limitation

For an unknown-length body, the gateway cannot know the final size before reading it. A bounded prefix, never more than the configured limit, may reach the assigned backend before overflow is detected. Keep equivalent request limits enabled in IIS and PHP. Multipart-aware pre-forward inspection and upload-specific limits remain future M2 work.

## Configuration

```json
{
  "Gateway": {
    "Urls": ["http://127.0.0.1:10000"],
    "ActivityTimeoutSeconds": 100,
    "MaximumRequestBytes": 6291456
  }
}
```

Invalid limits prevent startup. Do not increase the limit as a workaround for malformed requests; select the smallest value that supports documented legitimate traffic.

## Rollback

Restore the previous `MaximumRequestBytes` value and restart the laboratory gateway. Do not alter public IIS bindings, DNS, certificates, firewall rules, or Windows services.
