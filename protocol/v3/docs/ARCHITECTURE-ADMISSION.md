# Architecture-width and allocator admission

Draft 0.11 separates three concepts that MUST NOT be conflated:

```text
protocol integer range != address-space width != allocator capacity
```

`PlatformLimits` declares pointer width, total allocator ceiling and maximum permitted contiguous allocation. Runtime-cost admission is evaluated first; platform admission then verifies that the runtime working set and largest required contiguous working buffer fit the deployment.

A 32-bit target therefore does not automatically receive a 4 GiB memory budget simply because `usize` can represent values near that size. Embedded deployments SHOULD declare much smaller allocator and contiguous-allocation ceilings matching their actual allocator/RTOS/firmware configuration.

The Rust reference uses checked integer arithmetic and has `#![forbid(unsafe_code)]`. The repository still has no Python/Rust FFI boundary. Draft 0.11 adds a 32-bit Rust cross-compile gate to catch accidental architecture assumptions before such an embedded implementation is shipped.
