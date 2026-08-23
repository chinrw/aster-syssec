# Static candidate rules

The backend masks comments and string literals before matching. Handler scope
scans each `sys_*` handler and direct same-file callees. `--scope selected`
scans every function in the selected files without claiming reachability.

| Rule | Property | Candidate premise |
| --- | --- | --- |
| `RAW-DISPATCH-INFERRED-CAST` | `LINUX-ABI-CONTRACT` | The central raw-register adapter uses inferred `as _` conversion |
| `LOSSY-ABI-CAST` | `LINUX-ABI-CONTRACT` | A typed handler parameter is narrowed with `as` |
| `FLAGS-TRUNCATE-UNKNOWN` | `BOUNDARY-VALIDATION` | `from_bits_truncate` discards unknown flag bits |
| `UNCHECKED-RANGE-ARITHMETIC` | `BOUNDARY-VALIDATION` | Address, length, count, size, or offset arithmetic is not visibly checked |
| `REACHABLE-PANIC` | `BOUNDED-UNPRIVILEGED-WORK` | A reachable function contains `unwrap`, `expect`, `panic`, `todo`, or `unimplemented` |
| `DOUBLE-FETCH-USER-METADATA` | `BOUNDARY-VALIDATION` | The same user metadata address is read more than once |
| `COPYOUT-AFTER-SIDE-EFFECT` | `FAILURE-ATOMICITY` | A fallible copy-out follows an operation that may consume, publish, or mutate state |
| `LOCK-GUARD-ACROSS-BLOCKING` | `NO-BLOCK-IN-ATOMIC-CONTEXT` | A lock/borrow-shaped guard spans a wait, poll, socket operation, or allocation |
| `TYPED-STRUCT-COPYOUT` | `NO-UNINITIALIZED-COPYOUT` | A typed structure is copied to user memory and needs layout/initialization proof |

Confidence describes confidence that the source pattern exists, not confidence
that Asterinas violates a contract. The evidence and review requirement in each
candidate state what must be falsified next.

Known limitations:

- method dispatch and cross-file reachability are not resolved;
- macro expansion is not parsed, except for the concentrated syscall adapter
  rule;
- effect and guard rules are mechanism-shaped heuristics;
- layout safety is not established without layout tests and Miri;
- no rule establishes runtime impact.
