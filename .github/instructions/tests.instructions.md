---
applyTo: "tests/**/*"
---

# Test instructions

- Use xUnit and follow existing test naming and arrangement.
- Test public behavior and security invariants, including failure paths and boundary values.
- Use harmless synthetic content; never add functional webshells, credentials, tokens, or real customer data.
- Assert that unknown hosts fail closed, sites cannot cross-route, spoofed forwarding headers are replaced, and sensitive values do not appear in logs or responses.
- Use dynamically allocated ports for network tests. Never bind automated tests to ports 80, 443, 8081, 8082, or 10000.
- Keep tests deterministic, isolated, parallel-safe, and independent from IIS, WordPress, DNS, and Internet access.
- Cover cancellation, timeout, malformed input, and configured limits when testing asynchronous or streaming behavior.
- Run the smallest relevant tests during iteration and the full solution validation before completion.
