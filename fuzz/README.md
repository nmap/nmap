# Nmap Fuzzing

This directory contains libFuzzer-based fuzz targets.

Each fuzz target should expose

```c++
extern "C"
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
```

Targets should avoid sockets, timers, privilege changes, and other external
dependencies whenever possible.

Prefer fuzzing isolated parsing functions.

Shared helper routines belong in common.cc.
