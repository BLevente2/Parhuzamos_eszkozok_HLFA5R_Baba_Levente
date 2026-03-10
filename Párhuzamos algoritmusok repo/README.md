# Parallel Algorithms – Semester Project

This folder contains the three individual projects for the Parallel Algorithms course. Each subproject demonstrates a different parallelization technology. For each project, performance measurements are included to evaluate the effect of parallelism.

---

## 1. pthreads (C)
**Project:** Multi-threaded File Hashing  
**Description:**  
Processes multiple files in parallel using `pthread` in C. Each thread computes the hash of one file independently. Demonstrates thread creation, synchronization, and file I/O handling.

**How it will be executed:**  
The program will be run from the command line, taking a list of files or a directory path as input. Each file is processed in a separate thread.

**Performance measurements:**  
- Total execution time for hashing all files using 1, 2, 4, 8, and 16 threads (measured using `gettimeofday` or `clock_gettime`).
- Speedup and efficiency compared to the serial version.
- Optional: measure I/O bottlenecks (if any).

---

## 2. OpenMP (C)
**Project:** Block-wise Hashing of a Large File  
**Description:**  
Splits a large file into fixed-size blocks and computes a hash for each block in parallel using OpenMP. Demonstrates data-parallelism in a compute-heavy context.

**How it will be executed:**  
Run from the command line with parameters for input file and block size. The number of threads is controlled via the `OMP_NUM_THREADS` environment variable.

**Performance measurements:**  
- Execution time for varying block sizes and thread counts (1–16).
- Comparison with a serial implementation.
- Optional: investigate impact of chunk size and scheduling policy (`static`, `dynamic`, etc.).

---

## 3. C# Parallel Programming
**Project:** Parallel Block Encryption (AES-like)  
**Description:**  
Implements a simplified AES-256-like block cipher. The input is split into fixed-size blocks, each of which is encrypted in parallel using `Task`, `Parallel.For`, or async/await features.

**How it will be executed:**  
Run as a console application with parameters for input file and key. Outputs the encrypted file to disk. Optionally supports decryption as well.

**Performance measurements:**  
- Total encryption time with different parallel strategies (`Parallel.For`, manual `Task`, async).
- Execution time with varying number of blocks.
- CPU usage and comparison with single-threaded implementation.