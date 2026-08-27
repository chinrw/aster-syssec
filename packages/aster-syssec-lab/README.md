# aster-syssec-lab

This package owns the authorization boundary for Lab-only work. It depends on
`aster-syssec`; the core package never imports it.

The initial package validates authorization documents and reports its enforced
boundary. It does not execute fault plans, pause points, reproducers, kernel
sequence fuzzing, confirmation, or finding promotion.

```sh
syssec-lab boundary --json
syssec-lab authorization check --file authorization.json --json
```

Lab execution remains unavailable until a later, separately reviewed change
adds an authorization-bound VM operation.
