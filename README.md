# 🔍 scanner.py

A fast, multi-threaded TCP port scanner with service detection and banner grabbing — built in pure Python with no external dependencies.

---

## Features

- **Multi-threaded scanning** — configurable thread count for fast results
- **Service detection** — identifies 40+ common services by port number
- **Banner grabbing** — optional service banner retrieval
- **Flexible port targeting** — ranges (`1-1000`), lists (`22,80,443`), or top 100 common ports
- **Clean CLI output** — color-coded results with scan summary
- **File output** — save results to a text file

---

## Usage

```bash
# Scan default ports (1-1024) on a target
python scanner.py 192.168.1.1

# Scan a hostname with a custom range
python scanner.py scanme.nmap.org -p 1-10000

# Scan top 100 common ports with banner grabbing
python scanner.py 10.0.0.1 --top-ports -b

# Fast scan with 200 threads, save to file
python scanner.py 192.168.1.1 -p 1-65535 -t 200 -o results.txt

# Scan specific ports only
python scanner.py 192.168.1.1 -p 22,80,443,3306,8080
```

---

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `target` | IP address or hostname | required |
| `-p`, `--ports` | Port range or list | `1-1024` |
| `--top-ports` | Scan top 100 common ports | off |
| `-t`, `--threads` | Number of concurrent threads | `100` |
| `--timeout` | Connection timeout (seconds) | `1.0` |
| `-b`, `--banners` | Grab service banners | off |
| `-o`, `--output` | Save results to file | off |
| `-q`, `--quiet` | Minimal output (ports only) | off |

---

## Example Output

```
============================================================
  SCANNER.PY — Python Port Scanner
============================================================
  Target   : scanme.nmap.org  (45.33.32.156)
  Ports    : 1024 ports
  Threads  : 100
  Started  : 2026-05-13 14:22:01
============================================================

     22/tcp  OPEN  SSH
     80/tcp  OPEN  HTTP
    443/tcp  OPEN  HTTPS

============================================================
  3 open port(s) found in 4.87s
============================================================
```

---

## Requirements

- Python 3.10+
- No external libraries — uses only the standard library (`socket`, `threading`, `concurrent.futures`, `argparse`)

---

## Concepts Demonstrated

- TCP socket programming
- Multi-threading with `ThreadPoolExecutor`
- Thread-safe data access with `threading.Lock`
- CLI argument parsing with `argparse`
- Service enumeration and banner grabbing
- Network reconnaissance fundamentals

---

## Legal Notice

> Only scan systems you own or have explicit written permission to test. Unauthorized port scanning may be illegal in your jurisdiction. This tool is intended for educational purposes and authorized security assessments only.

---

## Author

**Michael Fletez**  
B.S. Cybersecurity — Northern Arizona University  
[linkedin.com/in/michaelfletez](https://linkedin.com/in/michaelfletez) | [github.com/michaelfletez](https://github.com/michaelfletez)
