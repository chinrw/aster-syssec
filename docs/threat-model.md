# Syscall threat model

## Attacker

An unprivileged, multithreaded process may:

- choose every syscall number and argument bit pattern;
- provide invalid, cross-page, partially mapped, overlapping, aliased, or
  concurrently modified user memory;
- race `close`, `dup`, `mmap`, `munmap`, `fork`, `exec`, signals, waits, and
  object publication;
- trigger `EFAULT`, `EINTR`, timeout, `ENOMEM`, `ENOSPC`, and partial progress;
- exhaust resources that an unprivileged process is permitted to allocate;
- coordinate threads to explore adversarial interleavings.

The attacker does not begin with root privileges, kernel-memory write access,
or a compromised verification host.

## Assets

- kernel integrity and availability;
- process, credential, capability, and namespace isolation;
- object identity, lifetime, ownership, and revocation;
- file, mapping, page, socket, and message confidentiality and integrity;
- resource ownership and accounting;
- supported Linux syscall semantics when a deviation affects security.

## Security properties

The machine-readable registry is
`src/aster_syssec/data/invariants.toml`:

- `BOUNDARY-VALIDATION`
- `AUTH-BEFORE-MUTATION`
- `OBJECT-IDENTITY-STABILITY`
- `NO-STALE-ACCESS`
- `FAILURE-ATOMICITY`
- `PARTIAL-PROGRESS-CONSISTENCY`
- `EXACTLY-ONCE-COMPLETION`
- `RESOURCE-ACCOUNTING-BALANCE`
- `NO-UNINITIALIZED-COPYOUT`
- `NO-BLOCK-IN-ATOMIC-CONTEXT`
- `BOUNDED-UNPRIVILEGED-WORK`
- `LINUX-ABI-CONTRACT`

Unsupported behavior is outside the security contract unless Asterinas or SCML
claims support. Linux-permitted nondeterminism and partial progress must remain
permitted by a model and reproducer oracle.
