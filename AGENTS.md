# Tessera Agent Bootstrap

Read `../LUCIDITY.md` before making architectural decisions in this repo.

Tessera owns key management, trust decisions, unwrap policy, certificates,
revocation, and audit. Femto and GalvoFS should call Tessera for trust and key
decisions rather than embedding that authority directly.

For cross-repo work:

- use `../Femto` for A2E execution and GalvoFS incubation;
- use `../Galvo` for agent-facing workflows;
- use `../KubeNyx` for Kubernetes operations.
