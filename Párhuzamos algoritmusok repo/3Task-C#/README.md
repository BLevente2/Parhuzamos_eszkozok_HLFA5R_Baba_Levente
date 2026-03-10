# Parallel Block Cipher Demo (AES-like 🛠️⚡)

> **Security disclaimer**  
> This implementation is **for educational and benchmarking purposes only**.  
> It is **not** a drop-in replacement for real AES. Do **not** use it to protect sensitive data in production.

---

## 1  What is it?
A cross-platform **.NET console application** that

* derives a 256-bit key from a pass-phrase (PBKDF2-SHA256)  
* splits any file into 16 byte blocks and encrypts/decrypts each block with a tiny AES-style algorithm  
* runs block processing **in parallel** using one of four strategies  
* prints timing, throughput, speed-up and per-thread efficiency

---

## 2  Features
| Feature | Notes |
|---------|-------|
| Simplified AES-like block cipher | 4 rounds, 16 B block, 256 bit key |
| Key derivation | PBKDF2-SHA256, 100 k iterations |
| Padding | PKCS#7 on **encrypt**, stripped on **decrypt** |
| Parallel strategies | `ParallelFor`, `TaskBased`, `AsyncAwait` + `SingleThreaded` baseline |
| Thread cap | `Threads` value (0 → logical core count) |
| Dual configuration | Fully CLI-driven *or* external `config.json` |
| Diagnostics | Size, parallel/single times, MB/s, speed-up, efficiency |
| Zero external dependencies | Pure BCL / .NET 6+ |

---

## 3  Building
```bash
git clone <repo>
cd ParallelBlockCipher
dotnet build -c Release
````

> Tested on **.NET 8.0**; .NET 6 and 7 also work.

---

## 4  Quick start

### 4.1 CLI only

```bash
dotnet run -c Release -- \
  --mode encrypt \
  --input  sample.txt \
  --output sample.enc \
  --password "SecretPass" \
  --strategy ParallelFor \
  --threads 8
```

### 4.2 `config.json`

```json
{
  "Mode":       "decrypt",
  "InputFile":  "sample.enc",
  "OutputFile": "sample.dec",
  "Password":   "SecretPass",
  "Strategy":   "AsyncAwait",
  "Threads":    4
}
```

Run with:

```bash
dotnet run -c Release -- config.json
# or
dotnet run -c Release -- --config config.json
# or put the file next to the exe and run with *no* arguments
```

---

## 5  Config reference

| Key / CLI switch          | Allowed values                                                   | Default           |
| ------------------------- | ---------------------------------------------------------------- | ----------------- |
| `Mode` / `--mode`         | `encrypt` \| `decrypt`                                           | *(required)*      |
| `InputFile` / `--input`   | path                                                             | –                 |
| `OutputFile` / `--output` | path                                                             | –                 |
| `Password` / `--password` | string                                                           | –                 |
| `Strategy` / `--strategy` | `SingleThreaded` \| `ParallelFor` \| `TaskBased` \| `AsyncAwait` | `SingleThreaded`  |
| `Threads` / `--threads`   | integer ≥ 0                                                      | `0` (= all cores) |

---

## 6  Parallel strategies

| Strategy         | How it works                                       | Honors `Threads` |
| ---------------- | -------------------------------------------------- | ---------------- |
| `SingleThreaded` | Plain for-loop                                     | n/a              |
| `ParallelFor`    | `Parallel.For` over block indices                  | **yes**          |
| `TaskBased`      | Batches of blocks in `Task.Run` – semaphore-capped | **yes**          |
| `AsyncAwait`     | One async task per block – semaphore-capped        | **yes**          |

---

## 7  Sample output

```
Encrypting...
Parallel finished.
Running reference single-threaded pass...
Reference finished.
Size              : 512.00 MB
Parallel time     : 12.637 s  (40.54 MB/s)
Single-thread time: 60.221 s  (8.50  MB/s)
Speed-up          : 4.77×
Efficiency/thread : 0.60
Done.
```

---

## 8  Extending the project

* Replace `AesLikeCipher` with a proper AES wrapper (e.g. `AesCng` or BouncyCastle) – just implement `IBlockCipher`.
* Add authenticated encryption (MAC or GCM) by wrapping the existing pipeline.
* Plug in a streaming API (`System.IO.Pipelines`) for huge files to keep memory constant.
* Unit-test skeletons are easy: feed known plaintext ⇒ encrypt ⇒ decrypt ⇒ compare.