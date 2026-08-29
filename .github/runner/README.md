# Disposable self-hosted runner contract

Mailstrix uses the shared `builder02`/`builder03` runner service. Each matching
self-hosted slot creates a fresh, single-job JIT runner identity and restores
that slot's trusted `pristine` golden snapshot after the job, whether the job
succeeds, fails, or is cancelled. Host deployment and snapshot management are
owned by that shared service; this repository must not require a project-only
organization runner group or a second dispatcher.

Workflows select the established `builder02` capacity with exactly one profile
label, `docker` or `lxc`. The runner-isolation workflow exercises both profiles
in serial job pairs. Its LXC pair uses the unique `b02lxc+lxc` selector; its
Docker pair uses the unique `builder02+docker` selector. These intersections
must remain single-slot selectors so each successor returns to the predecessor's
physical slot. Each first job records its JIT identity and leaves a file outside
`_work`; its successor must observe a different identity and no file. Together
those checks detect both identity reuse and failure to restore the slot's golden
snapshot between jobs.
