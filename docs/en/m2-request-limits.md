# M2.1: Bounded request controls

M2.1 adds absolute request-body safety controls. They are the foundation the multipart inspection
pass is built on: the request limit is what bounds the buffer described in
[bounded multipart inspection](m2-multipart-inspection.md), so nothing there can exceed what is
configured here. The gateway remains loopback-only and `Monitor` remains the default protection mode.

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
- WPShield never writes a request body to disk, and never holds a body larger than the configured limit. A `multipart/form-data` body is held in memory for the duration of the inspection pass, because Block mode has to decide before forwarding; every other request streams straight through and is never held. See [bounded multipart inspection](m2-multipart-inspection.md).

The HTTP 413 response is:

```json
{
  "error": "request_too_large",
  "requestId": "correlation-id"
}
```

Like every response WPShield generates, it now carries `X-WPShield-Request-ID`, `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`. Until this milestone it carried none of the three: `HttpResponse.Clear()` clears headers as well as the status code, so the 413 and 502 writers erased the correlation and nosniff headers the first middleware had set.

## Streaming limitation

For an unknown-length body, the gateway cannot know the final size before reading it, so the limit is enforced as the body is read.

- **On the buffered path** — a `multipart/form-data` request being inspected — the body is drained into the bounded buffer before the backend is contacted at all. If it crosses the limit, nothing has been forwarded and the 413 is complete.
- **On the streaming path** — every other request — a bounded prefix, never more than the configured limit, may reach the assigned backend before overflow is detected.

Keep equivalent request limits enabled in IIS and PHP regardless. They are the control that still applies when WPShield is bypassed or switched off.

## Configuration

```json
{
  "Gateway": {
    "Urls": ["http://127.0.0.1:10000"],
    "ActivityTimeoutSeconds": 100,
    "MaximumRequestBytes": 6291456,
    "Multipart": {
      "Enabled": true,
      "MaximumFileCount": 20,
      "MaximumFieldCount": 200,
      "MaximumPartHeaderBytes": 16384,
      "SampleBytes": 4096,
      "ReadTimeoutSeconds": 30
    }
  }
}
```

`MaximumRequestBytes` is the ceiling every multipart bound is measured against, which is why the two live in one section an operator reads together. Each `Gateway:Multipart` setting is documented in [bounded multipart inspection](m2-multipart-inspection.md).

Invalid limits prevent startup. Do not increase the limit as a workaround for malformed requests; select the smallest value that supports documented legitimate traffic.

## Rollback

Restore the previous `MaximumRequestBytes` value and restart the laboratory gateway. Do not alter public IIS bindings, DNS, certificates, firewall rules, or Windows services.
