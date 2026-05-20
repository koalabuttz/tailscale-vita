# SUPRX pthread_init investigation — 2026-05-13

**Status:** investigated, recommendation made, not yet implemented.

## Why this exists

Two attempts (2026-05-05 and 2026-05-12) to ship `tailscale-vita-plugin` as a SUPRX both hit the same crash: `pthread_init()` from the plugin's bootstrap context crashes silently, blocking `Runtime::up` from ever running. The 2026-05-12 attempt added `_init_vita_reent()` from the bootstrap thread — the trace confirmed our fix executed, but pthread_init still crashed without ever reaching the `rb1.5` trace marker after it.

This document is the writeup of investigation phases I1 + I2 from the approved plan, and the decision gate for what to do next.

## What we now know

### Phase I1 — Ecosystem precedent search

**No working SUPRX in the public Vita-homebrew ecosystem uses libc-pthread.** Evidence:

- `ftpeverywhere` (Vita FTP server, SUPRX): builds with `-nostdlib`, uses `sceKernelCreateThread` directly. No pthread.
- `vitacompanion` (FTP + cmd shell daemon, SUPRX loaded under `*main`): zero pthread references. Uses SCE primitives.
- 5 .suprx files pulled from the live Vita at `ur0:/tai/` (vitacompanion, pngshot, shellbat, psp2shell_m, henkaku): zero pthread references in `strings` output of any.
- `tailscale-rs/` (cloned locally as a reference impl) — uses pthread in `examples/` only; never deployed to Vita.
- Web search "vita taihen suprx Rust std::thread nostartfiles" returns zero results. We are pioneering this combination.

**Implication:** the established pattern for SUPRX threading is "use SCE primitives, link `-nostdlib`." Every working precedent sidesteps libc-pthread entirely.

### Phase I2 — Source-level analysis

Cloned `github.com/vitasdk/newlib` (branch `vita`) and `github.com/vitasdk/pthread-embedded` to read what pthread_init expects.

#### crt0's startup chain (newlib `libc/sys/vita/crt0.c`)

```
_start
  → _init_vita_newlib()         // heap, reent, malloc, io
  → __libc_init_array()         // runs all ctors in priority order
       → register_fini (priority 0)
       → pthread_setup (priority 101) -- this is the smoking gun
            → pthread_init()
            → __sinit(_REENT)
  → main()
  → __libc_fini_array()
  → exit(ret)
```

Our SUPRX uses `-nostartfiles`, so `_start` doesn't run. We manually replicate parts:
- `taipool_init` replaces `_init_vita_heap` + `_init_vita_malloc` (because newlib's `_sbrk` needs heap-init we skip)
- `_init_vita_reent()` ✅
- `_init_vita_io()` ✅
- `__libc_init_array()` ❌ — NEVER CALLED in our plugin

So `pthread_setup` never runs as a ctor. Then our bootstrap thread calls `pthread_init()` directly.

#### `_init_vita_reent` is single-shot (newlib `threading.c:235-243`)

```c
void _init_vita_reent(void)
{
    memset(reent_list, 0, sizeof(reent_list));
    _newlib_reent_mutex = sceKernelCreateMutex(...);  // <-- creates mutex
    reent_list[0].thread_id = sceKernelGetThreadId();
    _REENT_INIT_PTR(&reent_list[0].reent);
    *(struct _reent **)(TLS_REENT_PTR) = &reent_list[0].reent;
    _REENT_INIT_PTR(&_newlib_global_reent);
}
```

Calling this twice **leaks the first mutex and creates a new one**, plus resets `reent_list` and overwrites TLS slot 0x89 for whichever thread is calling. The 2026-05-12 attempt #1 (calling it from the bootstrap thread) was actively corrupting state, not just a no-op.

#### pthread_init internals (pthread-embedded `pthread_init.c:49-91`)

```c
int pthread_init(void) {
    if (pte_processInitialized) return PTE_TRUE;     // idempotency check
    pte_processInitialized = PTE_TRUE;
    pte_osInit();                                    // <-- ENTRY POINT for our crash
    pthread_key_create(&pte_selfThreadKey, NULL);
    pthread_key_create(&pte_cleanupKey, NULL);
    pte_osMutexCreate(&pte_thread_reuse_lock);
    // ... 5 more mutex creates ...
    return pte_processInitialized;
}
```

And `pte_osInit` (vita_osal.c:108-128):
```c
pte_osResult pte_osInit(void) {
    pspThreadData *pThreadData = malloc(sizeof(pspThreadData));     // needs working malloc ✅ taipool
    pspThreadData **addr = vitasdk_get_pthread_data(0);              // needs working reent
    pThreadData->evid = sceKernelCreateEventFlag(...);
    *addr = pThreadData;
    return PTE_OS_OK;
}
```

#### Init_array contents

Only **two ctors** in vitasdk's init_array:
- `register_fini` @ priority 0 (libc atexit chain)
- `pthread_setup` @ priority 101 (which IS `pthread_init() + __sinit(_REENT)`)

So walking `__init_array` from the SUPRX's module_start would call exactly the function that's already crashing. **Phase I3's walker experiment is structurally guaranteed to hit the same crash.** This is why we skipped it after Phase I2.

## Root-cause theory

**The SUPRX has statically-linked copies of libpthread + newlib state, separate from the eboot's copies.**

When the demo eboot launches:
1. The eboot's `_start` runs (via its crt0), executing **the eboot's** `_init_vita_newlib` + `__libc_init_array`.
2. The eboot's `pthread_setup` ctor calls **the eboot's** `pthread_init()`, which initializes **the eboot's** `pte_processInitialized` flag, **the eboot's** copy of `_newlib_reent_mutex`, **the eboot's** reent_list, etc.
3. Meanwhile, the SUPRX's `module_start` runs (in a separate code path / different time), with **the SUPRX's** copies of all that state.

Both ELFs share OS-level resources (TLS slot 0x89, SCE mutex handles) but each has its own private static state. When the SUPRX's `pthread_init` runs:
- It reads/writes the SUPRX's copies of state.
- TLS slot 0x89 contents may have been written by the eboot's libc and now get reinterpreted relative to the SUPRX's `reent_list[]` address — bogus pointer arithmetic.
- Or `pte_osMutexCreate` collides with mutex handles tracked in the eboot's copy.

We can't pinpoint the exact failing instruction without per-instruction debugging on Vita (no kgdb-equivalent for SUPRX). But the absence of any successful SUPRX-using-pthread example in the ecosystem strongly suggests this is a fundamental incompatibility, not a fixable bug.

## Three fix candidates

### Option A — Skip libc-pthread; use SCE primitives directly (RECOMMENDED)

Build the SUPRX `-nostdlib`. Replace all `std::thread::spawn` call sites with a small `vita-thread` crate wrapping `sceKernelCreateThread` + `sceKernelStartThread` + `sceKernelWaitThreadEnd`.

Spawn sites to migrate (from `grep -rE "thread::(Builder|spawn)" crates/`):
- `vita-log/src/lib.rs:75` — log writer thread
- `wg-engine/src/lib.rs:173` — WG engine pump
- `netstack/src/lib.rs:124` — netstack poll thread
- `ts-control/src/async_io.rs:104` — HTTP pump
- `ts-control/src/map.rs:734` — map client thread
- `ts-derp/src/probe.rs:76` — probe thread
- `ts-derp/src/conn.rs:130` — DERP conn recv loop
- `tailscale-vita/src/localapi.rs:92` — LocalAPI accept worker
- `ts-magicsock/src/lib.rs:308` — magicsock v4 worker
- `ts-magicsock/src/lib.rs:335` — magicsock v6 worker
- `tailscale-vita-rt/src/lib.rs:366` — runtime event loop

11 total. The wrapper is `cfg`-gated so the demo eboot keeps using std::thread (where it works) while the SUPRX uses SCE primitives.

Effort: 2-3 days.
Risk: medium — needs careful audit that no dep uses std::thread internally (crossbeam-channel, parking_lot — likely OK because they only use it for parking, not spawning). Audit per-crate during implementation.
Compatibility: ftpeverywhere + vitacompanion proved this pattern works.

### Option B — Walking __init_array from module_start (NOT RECOMMENDED)

Add ~5 lines to main.c that walk `__init_array_start..__init_array_end` BEFORE spawning the bootstrap thread. Would call `pthread_setup → pthread_init`.

Effort: 1 day.
Expected outcome: still crashes. Same code path that we already know crashes. We'd just be confirming what Phase I2 already analytically established.
Risk: HIGH (failure) — no path forward after.

### Option C — Custom crt0-lite shim, NID-export bridging, or patch vitasdk (NOT RECOMMENDED)

Make a SUPRX-aware version of pthread_init. Either:
- Replicate the eboot's full initialization sequence inside the SUPRX (with conflict awareness).
- Patch vitasdk to make libpthread state shareable across ELFs (would need upstream PR).
- Use NID-export bridging to have the SUPRX import the eboot's libpthread symbols rather than statically linking its own.

Effort: weeks. Requires understanding undocumented SCE behavior + vitasdk internals.
Risk: VERY HIGH — fragile, won't survive vitasdk upgrades.
Maintainability: poor.

## Recommendation

**Pursue Option A.** The investigation has high analytical certainty that fighting libc-pthread is the wrong path. The SCE-primitives approach is:
- Battle-tested by every other working SUPRX (ftpeverywhere, vitacompanion, all 5 plugins on the user's Vita).
- Smaller in code surface (we touch 11 spawn sites, not vitasdk internals).
- Smaller binary (no libpthread + libc statically linked into the SUPRX).
- More maintainable (no Vita-specific shims layered on top of vitasdk).

**Next milestone if pursuing: M15-A2.** Open a separate implementation plan covering:
1. `crates/vita-thread/` — new crate exposing `spawn(name, stack_kb, f) -> Handle` via SCE primitives. `cfg(any())`-gated to switch between SCE and std::thread by build target.
2. Update each of the 11 spawn sites to use `vita_thread::spawn` instead of `std::thread::Builder::new()`.
3. `tailscale-vita-plugin/CMakeLists.txt` — change `-nostartfiles` to `-nostdlib`, drop libpthread/libc links.
4. `tailscale-vita-rt/src/lib.rs` — drop the `pthread_init` call entirely (no longer needed).
5. Audit deps for hidden `std::thread::spawn` usage (`cargo tree -e features`, then grep).
6. Hardware verify — should reach `Runtime::up.start` from inside the plugin without crashing.

Estimate: 2-3 working days end-to-end.

## Decision

**Pursue Option A as M15-A2.** Open a fresh plan and milestone when ready. Until then, Tailscale runs in eboot mode (M15-C state); the user's Vita is already there from this session's earlier rollback.
