Profiling / Benchmarking

Build (Windows MinGW):
  mingw32-make clean
  mingw32-make all

Outputs:
  build\bin\bench_aes.exe
  build\bin\test_aes.exe
  build\bin\crypto_aes.dll
  build\lib\libcrypto_aes.dll.a
  build\lib\libcrypto_aes.a

Run benchmark:
  build\bin\bench_aes.exe

The benchmark prints throughput numbers for:
  - AES-128 / AES-192 / AES-256 CTR
  - AES-128 / AES-192 / AES-256 block encryption

No-instrumentation build (default):
  PROF=0 (default)

Optional internal instrumentation counters:
  mingw32-make clean
  mingw32-make PROF=1 all

Optional "fast" build flags (good for benchmarks on your current CPU):
  mingw32-make clean
  mingw32-make FAST=1 all

You can combine flags, e.g.:
  mingw32-make FAST=1 PROF=0 all

Optional gprof build (heavy):
  mingw32-make clean
  mingw32-make GPROF=1 all
  build\bin\bench_aes.exe
  gprof build\bin\bench_aes.exe gmon.out > gprof.txt
