---
applyTo: "**/*.cs"
---

# C# instructions

- Target .NET 10 and follow the repository's nullable, analyzer, and warnings-as-errors settings.
- Prefer clear, immutable models and explicit validation over defensive casts or broad exception handling.
- Keep `WPShield.Abstractions` platform-independent and keep `WPShield.Core` independent from ASP.NET Core and YARP where possible.
- Pass cancellation tokens through asynchronous I/O and never swallow cancellation.
- Bound all externally influenced sizes, counts, buffers, samples, and timeouts.
- Do not buffer complete request bodies or uploads and do not write suspicious content to disk.
- Use structured logging with stable event data. Never log secrets, sensitive headers, full query strings, request bodies, or upload content.
- Preserve multi-site isolation, loopback restrictions, explicit host routing, and `Monitor` as the default.
- Return privacy-safe client errors without exception details or internal destinations.
- Add focused tests for every behavior change.
