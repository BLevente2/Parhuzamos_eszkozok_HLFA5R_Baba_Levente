# Multi-threaded File Hasher

A simple C program that computes SHA-256 hashes of files in parallel using POSIX threads (pthreads), measures performance, and reports speedup and efficiency.

---

## Features

- Recursively scan a directory or accept a list of files
- Compute SHA-256 hash of each file in a separate thread
- Measure serial vs. parallel execution time
- Calculate speedup and per-thread efficiency
- Configurable thread count

---

## Requirements

- GCC (or any C99-compatible compiler)
- POSIX-compliant system (Linux, macOS, BSD)
- `pthread` library
- Make (optional)

---

## Building

1. Clone or copy the source files into one directory:
```

app.c
thread\_manager.c
hash\_store.c
checker.c
sha256.c
timer.c
util.c

````
2. Compile with GCC:
```bash
gcc -std=c99 -O2 \
    app.c thread_manager.c hash_store.c checker.c sha256.c timer.c util.c \
    -o filehasher -lpthread
````

3. (Optional) Create a Makefile to automate the above command.

---

## Usage

### 1. Generate hash database

Scan a directory (recursively) and write all file hashes to an output file.

```bash
./filehasher create <directory_path> <output_hash_file>
```

* `<directory_path>`: Path to the directory you want to hash.
* `<output_hash_file>`: Path where SHA-256 hashes and file paths will be saved.

Example:

```bash
./filehasher create ./data hashes.db
```

---

### 2. Verify files & measure performance

Compute hashes using **N** threads and compare against a stored hash file. Also prints serial and parallel timings, speedup, and efficiency.

```bash
./filehasher check <hash_file> <directory_path> <thread_count>
```

* `<hash_file>`: Path to the `.db` file generated earlier.
* `<directory_path>`: Directory containing files to verify.
* `<thread_count>`: Number of concurrent threads (e.g., 1, 2, 4, 8, 16).

Example:

```bash
./filehasher check hashes.db ./data 8
```

**Output example:**

```
Serial time   : 3.456789 s
Parallel time : 0.789012 s  (threads: 8)
Speedup        : 4.38×
Efficiency     : 54.8%
Verification  : OK (all hashes match)
```

---

## Performance Testing

To evaluate scalability:

1. Run the `check` command with different thread counts:

   ```bash
   for t in 1 2 4 8 16; do
     ./filehasher check hashes.db ./data $t
   done
   ```
2. Record serial vs. parallel times.
3. Compute:

   * **Speedup** = (serial time) ÷ (parallel time)
   * **Efficiency** = (speedup) ÷ (thread count) × 100%

Optionally, you can instrument I/O separately by timing just the file-reading loop in `file_hash_update()`.

---

## Notes & Tips

* Ensure large files fit in memory or adjust buffer size (`UTIL_BUFFER_SIZE` in `util.c`).
* Handle file-access errors gracefully (permissions, missing files).
* For very large directory trees, you may wish to limit thread creation or reuse threads via a thread pool.
* Feel free to extend to other hash algorithms (MD5, SHA-1) by swapping out the SHA-256 module.