#!/usr/bin/env python3
"""Порівняльний бенчмарк версій darkhttpd за допомогою wrk.

Запуск:
    python3 devel/bench_compare.py ВИХІД.csv КАТАЛОГ_ФАЙЛІВ назва=бінарник ...
Параметри середовища: BENCH_REPS (типово 5), BENCH_SECS (типово 5),
BENCH_SCENARIOS (фільтр за назвою, через кому).

Методика:
  * версії чергуються всередині кожного повтору, щоб дрейф системи
    (нагрівання, фонові задачі) не припадав на одну версію;
  * сервер закріплено на одному ядрі, wrk на інших, бо сервер однопотоковий;
  * для кожного запуску сервер стартує заново;
  * фіксується не лише RPS, а й затримка, помилки, CPU на запит і падіння
    сервера, бо RPS окремо приховує перевантаження або аварійне завершення.
"""
import collections
import csv
import os
import re
import signal
import socket
import statistics
import subprocess
import sys
import time

HOST = "127.0.0.1"
SERVER_CPU = "2"
WRK_CPUS = "4-11"
TCK = os.sysconf("SC_CLK_TCK")
REPS = int(os.environ.get("BENCH_REPS", "5"))
SECS = int(os.environ.get("BENCH_SECS", "5"))
FIELDS = ["version", "scenario", "rep", "rps", "p50_ms", "p99_ms", "requests",
          "socket_errors", "non_2xx", "cpu_us_per_req", "status"]

# (назва, файл, з'єднання wrk, режим, кількість простоюючих клієнтів)
SCENARIOS = [
    ("small_ka_100", "small.html", 100, "keepalive", 0),
    ("small_ka_500", "small.html", 500, "keepalive", 0),
    ("small_ka_2000", "small.html", 2000, "keepalive", 0),
    ("medium_ka_100", "medium.html", 100, "keepalive", 0),
    ("medium_ka_500", "medium.html", 500, "keepalive", 0),
    ("medium_ka_2000", "medium.html", 2000, "keepalive", 0),
    ("large_ka_100", "large.html", 100, "keepalive", 0),
    ("large_ka_500", "large.html", 500, "keepalive", 0),
    ("large_ka_2000", "large.html", 2000, "keepalive", 0),
    ("small_close_100", "small.html", 100, "close", 0),
    ("small_close_500", "small.html", 500, "close", 0),
    # Головний сценарій для epoll: багато неактивних клієнтів, мало активних.
    # 900 менше межі FD_SETSIZE, тому оригінал може працювати коректно.
    ("small_idle900", "small.html", 10, "keepalive", 900),
]

_port = [18600]


def to_ms(text):
    m = re.fullmatch(r"([\d.]+)(us|ms|s|m)", text)
    factor = {"us": 0.001, "ms": 1.0, "s": 1000.0, "m": 60000.0}[m.group(2)]
    return float(m.group(1)) * factor


def cpu_seconds(pid):
    with open(f"/proc/{pid}/stat") as f:
        rest = f.read().rsplit(")", 1)[1].split()
    return (int(rest[11]) + int(rest[12])) / TCK


def wait_up(port, proc):
    for _ in range(200):
        if proc.poll() is not None:
            return False
        try:
            socket.create_connection((HOST, port), 0.2).close()
            return True
        except OSError:
            time.sleep(0.02)
    return False


def parse_wrk(out):
    result = {"rps": 0.0, "p50_ms": "", "p99_ms": "", "requests": 0,
              "socket_errors": 0, "non_2xx": 0}
    m = re.search(r"Requests/sec:\s+([\d.]+)", out)
    if m:
        result["rps"] = float(m.group(1))
    m = re.search(r"(\d+) requests in", out)
    if m:
        result["requests"] = int(m.group(1))
    m = re.search(r"^\s+50%\s+(\S+)", out, re.M)
    if m:
        result["p50_ms"] = round(to_ms(m.group(1)), 3)
    m = re.search(r"^\s+99%\s+(\S+)", out, re.M)
    if m:
        result["p99_ms"] = round(to_ms(m.group(1)), 3)
    m = re.search(r"Socket errors: connect (\d+), read (\d+), write (\d+), "
                  r"timeout (\d+)", out)
    if m:
        result["socket_errors"] = sum(int(g) for g in m.groups())
    m = re.search(r"Non-2xx or 3xx responses: (\d+)", out)
    if m:
        result["non_2xx"] = int(m.group(1))
    return result


def run_one(version, binary, root, scenario, rep):
    name, filename, conns, mode, idle = scenario
    _port[0] += 1
    port = _port[0]
    server = subprocess.Popen(
        ["taskset", "-c", SERVER_CPU, binary, root, "--port", str(port),
         "--addr", HOST],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    sockets = []
    row = {"version": version, "scenario": name, "rep": rep}
    try:
        if not wait_up(port, server):
            row.update(parse_wrk(""), cpu_us_per_req="", status="НЕ СТАРТУВАВ")
            return row
        for _ in range(idle):
            s = socket.socket()
            s.connect((HOST, port))
            sockets.append(s)
        if idle:
            time.sleep(0.5)
        cmd = ["taskset", "-c", WRK_CPUS, "wrk", "-t4", f"-c{conns}",
               f"-d{SECS}s", "--latency", f"http://{HOST}:{port}/{filename}"]
        if mode == "close":
            cmd[5:5] = ["-H", "Connection: close"]
        before = cpu_seconds(server.pid)
        out = subprocess.run(cmd, capture_output=True, text=True).stdout
        parsed = parse_wrk(out)
        code = server.poll()
        cpu = "" if code is not None or not parsed["requests"] else round(
            (cpu_seconds(server.pid) - before) * 1e6 / parsed["requests"], 2)
        status = "OK" if code is None else f"ПАДІННЯ (код {code})"
        row.update(parsed, cpu_us_per_req=cpu, status=status)
        return row
    finally:
        for s in sockets:
            s.close()
        if server.poll() is None:
            server.send_signal(signal.SIGTERM)
        try:
            _, err = server.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            _, err = server.communicate()
        if row.get("status", "").startswith("ПАДІННЯ"):
            text = err.decode(errors="replace").strip().splitlines()
            row["status"] += ": " + (text[0] if text else "без повідомлення")


def fmt(values, digits=0):
    values = [float(v) for v in values if v != ""]
    if not values:
        return "-"
    mean = statistics.mean(values)
    sd = statistics.stdev(values) if len(values) > 1 else 0.0
    return f"{mean:.{digits}f}±{sd:.{digits}f}"


def summary(rows):
    grouped = collections.defaultdict(list)
    versions, names = [], []
    for row in rows:
        grouped[row["scenario"], row["version"]].append(row)
        if row["version"] not in versions:
            versions.append(row["version"])
        if row["scenario"] not in names:
            names.append(row["scenario"])
    print(f"{'сценарій':17}{'версія':11}{'RPS':>18}{'p50 мс':>14}{'p99 мс':>16}"
          f"{'CPU мкс/запит':>16}{'помилки':>9}  стан")
    for name in names:
        for version in versions:
            g = grouped[name, version]
            ok = [r for r in g if r["status"] == "OK"]
            errors = sum(int(r["socket_errors"]) + int(r["non_2xx"]) for r in g)
            state = "OK" if len(ok) == len(g) else \
                f"{len(g) - len(ok)}/{len(g)} збоїв: {g[0]['status']}" \
                if not ok else f"{len(g) - len(ok)}/{len(g)} збоїв"
            print(f"{name:17}{version:11}{fmt([r['rps'] for r in ok]):>18}"
                  f"{fmt([r['p50_ms'] for r in ok], 2):>14}"
                  f"{fmt([r['p99_ms'] for r in ok], 2):>16}"
                  f"{fmt([r['cpu_us_per_req'] for r in ok], 1):>16}"
                  f"{errors:>9}  {state}")


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    output, root = sys.argv[1], sys.argv[2]
    versions = [a.split("=", 1) for a in sys.argv[3:]]
    wanted = os.environ.get("BENCH_SCENARIOS")
    scenarios = [s for s in SCENARIOS
                 if not wanted or s[0] in wanted.split(",")]
    rows = []
    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, FIELDS)
        writer.writeheader()
        for rep in range(1, REPS + 1):
            for scenario in scenarios:
                for version, binary in versions:
                    row = run_one(version, binary, root, scenario, rep)
                    rows.append(row)
                    writer.writerow(row)
                    f.flush()
                    time.sleep(0.5)
            print(f"повтор {rep}/{REPS} завершено", flush=True)
    summary(rows)


if __name__ == "__main__":
    main()
