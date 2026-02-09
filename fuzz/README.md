# Fuzz Testing for Nmap

This directory contains fuzz targets for nmap's parsing subsystems,
designed for use with [libFuzzer](https://llvm.org/docs/LibFuzzer.html)
and [OSS-Fuzz](https://github.com/google/oss-fuzz).

## Fuzz targets

| Target | Description |
|--------|-------------|
| `fuzz_target_parse` | Fuzzes target specification parsing (CIDR, octet ranges, IPv6, hostnames) |

## Building locally

```bash
clang++ -g -fsanitize=fuzzer,address fuzz_target_parse.cc -o fuzz_target_parse
./fuzz_target_parse corpus/
```

## OSS-Fuzz integration

These targets are continuously fuzzed via Google's OSS-Fuzz infrastructure.
