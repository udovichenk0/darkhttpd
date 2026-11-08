#!/usr/bin/env python3
"""Автотести безпеки для darkhttpd: перевірки SEC-01..SEC-10.

Запуск (лише на локальному інтерфейсі 127.0.0.1):
    python3 devel/test_security.py РОБОЧА_ТЕКА БІНАРНИК [БІНАРНИК ...]

Для кожного бінарника друкується таблиця: ЗАХИЩЕНО, ВРАЗЛИВО або
НЕМАЄ ФУНКЦІЇ, якщо версія сервера не має потрібного параметра. Так одна
команда дає колонки «оригінал / epoll / фінальна» для таблиці в роботі.

Перевірка SEC-10 потребує збірки з -fsanitize=address, інакше вона
пропускається. Код виходу 1, якщо останній бінарник у списку вразливий.
"""
import os
import resource
import signal
import socket
import subprocess
import sys
import time

HOST = "127.0.0.1"
SIZE = 20 * 1024 * 1024
TCK = os.sysconf("SC_CLK_TCK")
BIG = b"GET /big.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
SAFE, VULN, NA = "ЗАХИЩЕНО", "ВРАЗЛИВО", "НЕМАЄ ФУНКЦІЇ"
_port = [18300]


def next_port():
    _port[0] += 1
    return _port[0]


class Server:
    """Запускає сервер як дочірній процес і гарантовано зупиняє його."""

    def __init__(self, binary, root, args=(), nofile=None, keep_fds=(),
                 stderr=subprocess.DEVNULL):
        self.port = next_port()
        def limit():
            if nofile:
                resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
        self.proc = subprocess.Popen(
            [binary, root, "--port", str(self.port), "--addr", HOST, *args],
            stdout=subprocess.DEVNULL, stderr=stderr, preexec_fn=limit,
            pass_fds=keep_fds)
        for _ in range(100):
            try:
                socket.create_connection((HOST, self.port), 0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            self.stop()
            raise RuntimeError("сервер не запустився")
        time.sleep(0.15)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stop()

    def stop(self):
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGCONT)
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def cpu(self):
        with open(f"/proc/{self.proc.pid}/stat") as f:
            rest = f.read().rsplit(")", 1)[1].split()
        return (int(rest[11]) + int(rest[12])) / TCK

    def connect(self, rcvbuf=None, timeout=2):
        s = socket.socket()
        s.settimeout(timeout)
        if rcvbuf:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        s.connect((HOST, self.port))
        return s


def read_all(s, timeout=4, limit=SIZE * 2):
    """Читає до закриття. Повертає (дані, чи стався тайм-аут)."""
    s.settimeout(timeout)
    out = bytearray()
    try:
        while len(out) < limit:
            chunk = s.recv(1 << 20)
            if not chunk:
                return bytes(out), False
            out += chunk
    except socket.timeout:
        return bytes(out), True
    except OSError:
        return bytes(out), False
    return bytes(out), False


def body_len(data):
    return len(data.split(b"\r\n\r\n", 1)[1]) if b"\r\n\r\n" in data else 0


def headers(data):
    return data.split(b"\r\n\r\n", 1)[0].split(b"\r\n")


def supports(binary, flag):
    out = subprocess.run([binary, "--help"], capture_output=True).stdout
    return flag.encode() in out


def make_root(work):
    root = os.path.join(work, "www")
    os.makedirs(os.path.join(root, "dir"), exist_ok=True)
    with open(os.path.join(root, "big.bin"), "wb") as f:
        f.write(b"x" * SIZE)
    with open(os.path.join(root, "small.txt"), "wb") as f:
        f.write(b"hello\n")
    return root


def get_small(srv):
    s = srv.connect()
    s.sendall(b"GET /small.txt HTTP/1.0\r\n\r\n")
    data, _ = read_all(s, timeout=3)
    s.close()
    return data.startswith(b"HTTP/1.1 200")


def test_sec01_request_before_accept(binary, root, asan):
    """Запит приходить раніше accept(): файл має дійти повністю."""
    with Server(binary, root) as srv:
        os.kill(srv.proc.pid, signal.SIGSTOP)
        s = srv.connect()
        s.sendall(BIG)
        time.sleep(0.2)
        os.kill(srv.proc.pid, signal.SIGCONT)
        data, _ = read_all(s)
        s.close()
        got = body_len(data)
        return got == SIZE, f"отримано {got} із {SIZE} байтів"


def test_sec02_half_close(binary, root, asan):
    """Half-close і відсутність читання не мають навантажувати CPU."""
    with Server(binary, root) as srv:
        s = srv.connect(rcvbuf=4096)
        time.sleep(0.3)
        s.sendall(BIG)
        s.shutdown(socket.SHUT_WR)
        time.sleep(0.5)
        start = srv.cpu()
        time.sleep(3)
        used = srv.cpu() - start
        s.close()
        return used < 0.5, f"CPU {used:.2f} с за 3 с"


def test_sec03_fd_exhaustion(binary, root, asan):
    """При EMFILE немає зациклення, а після звільнення сервер працює."""
    # Успадковані дескриптори займають майже весь ліміт, щоб accept()
    # отримав EMFILE незалежно від того, який conn_limit обчислив сервер.
    fds = [os.open("/dev/null", os.O_RDONLY) for _ in range(50)]
    held = []
    try:
        with Server(binary, root, nofile=64, keep_fds=fds) as srv:
            for _ in range(30):
                try:
                    held.append(srv.connect(timeout=0.5))
                except OSError:
                    break
            time.sleep(0.5)
            start = srv.cpu()
            time.sleep(3)
            used = srv.cpu() - start
            for s in held:
                s.close()
            held = []
            time.sleep(0.5)
            recovered = get_small(srv)
            return (used < 0.5 and recovered,
                    f"CPU {used:.2f} с за 3 с, відновлення: {recovered}")
    finally:
        for s in held:
            s.close()
        for fd in fds:
            os.close(fd)


def test_sec04_reuseport(binary, root, asan):
    """Другий екземпляр не має запускатися на зайнятому порту."""
    with Server(binary, root) as srv:
        second = subprocess.Popen(
            [binary, root, "--port", str(srv.port), "--addr", HOST],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.7)
        running = second.poll() is None
        if running:
            second.terminate()
            second.wait()
        return not running, f"другий екземпляр працює: {running}"


def test_sec05_crlf(binary, root, asan):
    """Закодований CRLF не має створювати новий заголовок відповіді."""
    with Server(binary, root, ("--forward-all", "http://target.test")) as srv:
        s = srv.connect()
        s.sendall(b"GET /a%0d%0aSet-Cookie:%20pwn=1 HTTP/1.0\r\n\r\n")
        data, _ = read_all(s, timeout=2)
        s.close()
        injected = any(h.lower().startswith(b"set-cookie") for h in headers(data))
        return not injected, headers(data)[0].decode()


def test_sec06_open_redirect(binary, root, asan):
    """Location не має вказувати на сторонній хост."""
    evil = [b"//evil.example/../dir", b"/\\evil.example/../dir",
            b"http://evil.example/dir"]
    bad = []
    with Server(binary, root) as srv:
        for target in evil:
            s = srv.connect()
            s.sendall(b"GET " + target + b" HTTP/1.0\r\n\r\n")
            data, _ = read_all(s, timeout=2)
            s.close()
            for h in headers(data):
                if h.lower().startswith(b"location:"):
                    value = h.split(b":", 1)[1].strip()
                    if not value.startswith(b"/") or value[:2] in (b"//", b"/\\"):
                        bad.append(value.decode(errors="replace"))
    return not bad, f"небезпечні Location: {bad}" if bad else "Location локальний"


def test_sec07_maxconn(binary, root, asan):
    """Понад --maxconn клієнт чекає, а CPU не витрачається."""
    with Server(binary, root, ("--maxconn", "5")) as srv:
        held = [srv.connect() for _ in range(5)]
        time.sleep(0.4)
        extra = srv.connect()
        extra.sendall(b"GET /small.txt HTTP/1.0\r\n\r\n")
        start = srv.cpu()
        data, _ = read_all(extra, timeout=1.5)
        used = srv.cpu() - start
        served_over_limit = bool(data)
        held[0].close()
        late, _ = read_all(extra, timeout=3)
        extra.close()
        for s in held[1:]:
            s.close()
        ok = (not served_over_limit and used < 0.5
              and late.startswith(b"HTTP/1.1 200"))
        return ok, (f"6-й клієнт обслужений понад ліміт: {served_over_limit}, "
                    f"CPU {used:.2f} с, обслужений після звільнення: "
                    f"{late.startswith(b'HTTP/1.1 200')}")


def test_sec08_per_ip(binary, root, asan):
    """Зайві з'єднання з однієї адреси відхиляються."""
    if not supports(binary, "--maxconn-per-ip"):
        return None, "параметра --maxconn-per-ip немає"
    with Server(binary, root, ("--maxconn-per-ip", "3")) as srv:
        held = [srv.connect() for _ in range(3)]
        time.sleep(0.3)
        extra = srv.connect()
        extra.sendall(b"GET /small.txt HTTP/1.0\r\n\r\n")
        data, _ = read_all(extra, timeout=1.5)
        extra.close()
        for s in held:
            s.close()
        time.sleep(0.3)
        recovered = get_small(srv)
        return (not data and recovered,
                f"4-й клієнт обслужений: {bool(data)}, відновлення: {recovered}")


def test_sec09_slowloris(binary, root, asan):
    """Повільні заголовки мають обриватися попри постійну активність."""
    args = ["--timeout", "4"]
    if supports(binary, "--header-timeout"):
        args += ["--header-timeout", "3"]
    with Server(binary, root, args) as srv:
        s = srv.connect()
        msg = b"GET /small.txt HTTP/1.0\r\nX: aaaaaaaa"
        try:
            for i in range(8):
                s.sendall(msg[i:i + 1])
                time.sleep(1)
            s.sendall(msg[8:] + b"\r\n\r\n")
            data, _ = read_all(s, timeout=2)
        except OSError:
            data = b""
        s.close()
        return not data, f"запит на 8 с обслужено: {bool(data)}"


def test_sec10_oversized(binary, root, asan):
    """Завеликий запит отримує 413 без витоку пам'яті (лише ASan)."""
    if not asan:
        return None, "потрібна збірка з ASan"
    srv = Server(binary, root, stderr=subprocess.PIPE)
    try:
        s = srv.connect()
        s.sendall(b"GET /dir/ HTTP/1.0\r\nX-Pad: " + b"a" * 5000 + b"\r\n\r\n")
        data, _ = read_all(s, timeout=2)
        s.close()
    finally:
        srv.proc.terminate()
        _, err = srv.proc.communicate(timeout=20)
    summary = [l for l in err.decode(errors="replace").splitlines()
               if "SUMMARY" in l]
    ok = data.split(b"\r\n")[0].startswith(b"HTTP/1.1 413") and not summary
    return ok, summary[0] if summary else "ASan без зауважень"


TESTS = [test_sec01_request_before_accept, test_sec02_half_close,
         test_sec03_fd_exhaustion, test_sec04_reuseport, test_sec05_crlf,
         test_sec06_open_redirect, test_sec07_maxconn, test_sec08_per_ip,
         test_sec09_slowloris, test_sec10_oversized]


def is_asan(binary):
    with open(binary, "rb") as f:
        return b"__asan_init" in f.read()


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    work, binaries = sys.argv[1], sys.argv[2:]
    root = make_root(work)
    failed = False
    for binary in binaries:
        print(f"\n== {os.path.basename(binary)}")
        asan = is_asan(binary)
        failed = False
        for test in TESTS:
            try:
                ok, note = test(binary, root, asan)
            except Exception as e:
                ok, note = False, f"помилка тесту: {e!r}"
            status = NA if ok is None else (SAFE if ok else VULN)
            failed = failed or ok is False
            name = test.__name__.replace("test_", "", 1)
            print(f"  {name:34} {status:14} {note}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
