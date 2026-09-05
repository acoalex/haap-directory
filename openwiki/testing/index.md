# Files

- [Test Suite — Fixtures, Seams & Phase Mapping](test-suite.md) - How the HAAP directory enforces correctness — the shared tests/conftest.py fixtures (real HTTP on an ephemeral port, MutableClock, StubResolver, Agent signing kit), the phase-mapped test files F0–F6, the HAAP_REPO-gated compat test, and the hard rules (injected clock only, no real DNS/network, every rejection asserts its stable code and HTTP status).
