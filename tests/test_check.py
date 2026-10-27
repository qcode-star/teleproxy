#!/usr/bin/env python3
"""E2E tests for the `teleproxy check` diagnostic subcommand.

Tests exit codes, output format, and individual checks.
Runs inside a Docker container with the teleproxy binary available.
"""
import os
import re
import socket
import subprocess
import sys
import tempfile

BIN = os.environ.get("TELEPROXY_BIN", "/usr/local/bin/teleproxy")

passed = 0
failed = 0


def run_check(*args, timeout=30):
    """Run teleproxy check with given args, return (exit_code, stdout, stderr)."""
    cmd = [BIN, "check"] + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def generate_secret():
    """Generate a random 32-char hex secret."""
    r = subprocess.run([BIN, "generate-secret"], capture_output=True, text=True)
    return r.stdout.strip()


def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        msg = f"  FAIL  {name}"
        if detail:
            msg += f"\n        {detail}"
        print(msg)


# ── Exit code tests ──────────────────────────────────────────────

print("=== Exit code tests ===")

secret = generate_secret()

# 1. Valid direct config → exit 0
code, out, err = run_check("--direct", "-S", secret)
check("valid direct config → exit 0",
      code == 0,
      f"got exit {code}\nstdout: {out[:200]}")

# 2. Valid TOML config → exit 0
with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
    f.write(f'direct = true\n\n[[secret]]\nkey = "{secret}"\n')
    toml_path = f.name
try:
    code, out, err = run_check("--config", toml_path)
    check("valid TOML config → exit 0",
          code == 0,
          f"got exit {code}\nstdout: {out[:200]}")
finally:
    os.unlink(toml_path)

# 3. No arguments → exit 2
code, out, err = run_check()
check("no arguments → exit 2",
      code == 2,
      f"got exit {code}")

# 4. Nonexistent config → exit 2
code, out, err = run_check("--config", "/nonexistent.toml")
check("nonexistent config → exit 2",
      code == 2,
      f"got exit {code}")

# 5. Malformed TOML → exit 2
with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
    f.write("this is {broken\n")
    bad_toml = f.name
try:
    code, out, err = run_check("--config", bad_toml)
    check("malformed TOML → exit 2",
          code == 2,
          f"got exit {code}")
finally:
    os.unlink(bad_toml)

# 6. Invalid secret (wrong length) → exit 2
code, out, err = run_check("--direct", "-S", "abcd")
check("invalid secret length → exit 2",
      code == 2,
      f"got exit {code}")

# 7. Invalid secret (non-hex) → exit 2
code, out, err = run_check("--direct", "-S", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
check("non-hex secret → exit 2",
      code == 2,
      f"got exit {code}")

# 8. Direct mode with no secret → warns but exit 0
code, out, err = run_check("--direct")
check("direct, no secret → exit 0 with WARN",
      code == 0 and "WARN" in out,
      f"got exit {code}, WARN in output: {'WARN' in out}")


# ── DC connectivity tests ────────────────────────────────────────

print("\n=== DC connectivity tests ===")

# 9. All 5 DCs pass (container has internet)
code, out, err = run_check("--direct", "-S", secret)
for dc in range(1, 6):
    check(f"DC {dc} connectivity",
          f"DC {dc}" in out and "OK" in out.split(f"DC {dc}")[1].split("\n")[0],
          f"DC {dc} not found or not OK in output")

# 10. Unreachable DC override (localhost port 1 — always refused) → exit 1
code, out, err = run_check("--direct", "-S", secret,
                            "--dc-override", "1:127.0.0.1:1")
check("unreachable DC override → exit 1",
      code == 1,
      f"got exit {code}\nstdout: {out[:300]}")
check("overridden DC 1 shows FAIL",
      "DC 1" in out and "FAIL" in out.split("DC 1")[1].split("\n")[0],
      f"output: {out[:300]}")


# ── NTP test ─────────────────────────────────────────────────────

print("\n=== NTP clock test ===")

# 11. Clock sync check runs
code, out, err = run_check("--direct", "-S", secret)
check("clock sync present in output",
      "Clock" in out,
      f"output: {out[:200]}")
clock_line = [l for l in out.split("\n") if "Clock" in l]
if clock_line:
    check("clock sync OK or WARN (not FAIL)",
          "OK" in clock_line[0] or "WARN" in clock_line[0],
          f"line: {clock_line[0]}")
else:
    check("clock sync OK or WARN (not FAIL)", False, "no clock line found")


# ── TLS domain probe tests ───────────────────────────────────────

print("\n=== TLS domain probe tests ===")

# 12. Valid domain probe (google.com is universally accessible)
code, out, err = run_check("--direct", "-S", secret, "-D", "google.com")
tls_lines = [l for l in out.split("\n") if "TLS google.com" in l]
check("TLS google.com present",
      len(tls_lines) > 0,
      f"output: {out[:300]}")
if tls_lines:
    check("TLS google.com → OK with TLS 1.3",
          "OK" in tls_lines[0] and "TLS 1.3" in tls_lines[0],
          f"line: {tls_lines[0]}")
else:
    check("TLS google.com → OK with TLS 1.3", False, "no TLS line")

# 13. Unreachable domain → FAIL
code, out, err = run_check("--direct", "-S", secret, "-D", "nonexistent.invalid")
check("unreachable domain → exit 1",
      code == 1,
      f"got exit {code}")
tls_lines = [l for l in out.split("\n") if "TLS nonexistent" in l]
check("TLS nonexistent.invalid → FAIL",
      len(tls_lines) > 0 and "FAIL" in tls_lines[0],
      f"lines: {tls_lines}")

# 14. SNI mismatch warning (domain IP != container IP)
code, out, err = run_check("--direct", "-S", secret, "-D", "google.com")
sni_lines = [l for l in out.split("\n") if "SNI" in l]
check("SNI check present for domain",
      len(sni_lines) > 0,
      f"output: {out[:300]}")


# ── Output format tests ──────────────────────────────────────────

print("\n=== Output format tests ===")

code, out, err = run_check("--direct", "-S", secret, "-D", "google.com")

# 15. Summary line present
lines = out.strip().split("\n")
last_line = lines[-1].strip() if lines else ""
check("summary line present",
      re.match(r"\d+ passed, \d+ failed, \d+ warning", last_line),
      f"last line: '{last_line}'")

# 16. Config summary
check("config summary in output",
      "mode: direct" in out,
      f"output: {out[:200]}")

# 17. Header line
check("header line present",
      "teleproxy check" in out,
      f"output: {out[:100]}")

# 18. Dot alignment (each result line has dots)
result_lines = [l for l in lines if ".." in l and ("OK" in l or "FAIL" in l or "WARN" in l or "SKIP" in l)]
check("result lines have dot alignment",
      len(result_lines) >= 7,
      f"found {len(result_lines)} aligned result lines")


# ── CDN DC override tests ────────────────────────────────────────

print("\n=== CDN DC override tests ===")


def tcp_listener():
    """Listen on a free localhost port; connects succeed via the backlog."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(64)
    return s


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def dc_line(out, dc):
    """Return the result line for DC <dc>, or '' if absent."""
    for l in out.split("\n"):
        if l.strip().startswith(f"DC {dc} "):
            return l
    return ""


def write_toml(overrides):
    """Write a direct-mode TOML config with the given (dc, host, port) rows."""
    body = f'direct = true\n\n[[secret]]\nkey = "{secret}"\n'
    for dc, host, port in overrides:
        body += f'\n[[dc_override]]\ndc = {dc}\nhost = "{host}"\nport = {port}\n'
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(body)
        return f.name


def run_proxy(*args, wait=3):
    """Start the proxy; return (exit_code or None if still running, output)."""
    cmd = [BIN, "-H", str(free_port())] + list(args)
    if os.geteuid() == 0:
        # As root the engine drops privileges to 'teleproxy', absent here
        cmd[1:1] = ["-u", "nobody"]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True)
    try:
        out, _ = p.communicate(timeout=wait)
        return p.returncode, out
    except subprocess.TimeoutExpired:
        p.terminate()
        out, _ = p.communicate(timeout=10)
        return None, out


listener = tcp_listener()
cdn_port = listener.getsockname()[1]

# 19. Overridden CDN DC is probed → OK
code, out, err = run_check("--direct", "-S", secret,
                           "--dc-override", f"203:127.0.0.1:{cdn_port}")
check("CLI override for CDN DC 203 → exit 0",
      code == 0,
      f"got exit {code}\nstdout: {out[:500]}\nstderr: {err[:300]}")
check("CDN DC 203 probed and OK",
      "OK" in dc_line(out, 203),
      f"line: '{dc_line(out, 203)}'")

# 20. Unreachable CDN override is reported, not silently accepted → exit 1
code, out, err = run_check("--direct", "-S", secret,
                           "--dc-override", "203:127.0.0.1:1")
check("unreachable CDN override → exit 1",
      code == 1,
      f"got exit {code}\nstdout: {out[:500]}")
check("CDN DC 203 shows FAIL",
      "FAIL" in dc_line(out, 203),
      f"line: '{dc_line(out, 203)}'")

# 21. CDN DCs without an override are not probed
code, out, err = run_check("--direct", "-S", secret)
check("no CDN lines without override",
      not re.search(r"^\s*DC 2\d\d ", out, re.M),
      f"output: {out[:500]}")

# 22. Ids outside 1-5 and 201-299 are rejected → exit 2
for bad in ("0", "6", "200", "300"):
    code, out, err = run_check("--direct", "-S", secret,
                               "--dc-override", f"{bad}:127.0.0.1:1")
    check(f"CLI override for DC {bad} rejected",
          code == 2 and "201-299" in err,
          f"got exit {code}\nstderr: {err[:300]}")

# 23. TOML CDN override is probed too
path = write_toml([(203, "127.0.0.1", cdn_port)])
try:
    code, out, err = run_check("--config", path)
    check("TOML override for CDN DC 203 → exit 0 and OK",
          code == 0 and "OK" in dc_line(out, 203),
          f"got exit {code}\nstdout: {out[:500]}\nstderr: {err[:300]}")
finally:
    os.unlink(path)

# 24. TOML rejects ids outside the ranges
path = write_toml([(300, "127.0.0.1", 1)])
try:
    code, out, err = run_check("--config", path)
    check("TOML override for DC 300 rejected",
          code == 2 and "201-299" in err,
          f"got exit {code}\nstderr: {err[:300]}")
finally:
    os.unlink(path)

# 25. TOML accepts up to 16 override rows, rejects more
rows = [(201 + i, "127.0.0.1", cdn_port) for i in range(16)]
path = write_toml(rows)
try:
    code, out, err = run_check("--config", path)
    check("TOML with 16 override rows → exit 0",
          code == 0,
          f"got exit {code}\nstdout: {out[:500]}\nstderr: {err[:300]}")
finally:
    os.unlink(path)
path = write_toml(rows + [(217, "127.0.0.1", cdn_port)])
try:
    code, out, err = run_check("--config", path)
    check("TOML with 17 override rows rejected",
          code == 2 and "too many dc_override" in err,
          f"got exit {code}\nstderr: {err[:300]}")
finally:
    os.unlink(path)

# 26. A TOML row that cannot be applied is an error, not silently dropped
path = write_toml([(203, "not-an-ip", 443)])
try:
    code, out, err = run_check("--config", path)
    check("TOML override with bad host rejected",
          code == 2 and "dc_override[0]" in err,
          f"got exit {code}\nstderr: {err[:300]}")
finally:
    os.unlink(path)

# 27. The proxy itself refuses an invalid --dc-override instead of ignoring it
code, out = run_proxy("--direct", "-S", secret,
                      "--dc-override", "300:127.0.0.1:443")
check("proxy exits on --dc-override 300",
      code is not None and code != 0 and "201-299" in out,
      f"exit {code}\noutput: {out[-500:]}")

# 28. ...and starts with a CDN override
code, out = run_proxy("--direct", "-S", secret,
                      "--dc-override", "203:127.0.0.1:443")
check("proxy starts with --dc-override 203",
      code is None,
      f"exit {code}\noutput: {out[-500:]}")

# 29. The proxy also refuses a TOML override it cannot apply
path = write_toml([(203, "not-an-ip", 443)])
try:
    code, out = run_proxy("--config", path)
    check("proxy exits on TOML override with bad host",
          code == 1 and "dc_override[0]" in out,
          f"exit {code}\noutput: {out[-500:]}")
finally:
    os.unlink(path)

listener.close()


# ── Summary ──────────────────────────────────────────────────────

print(f"\n{'=' * 40}")
print(f"Results: {passed} passed, {failed} failed")

if failed > 0:
    sys.exit(1)
print("All tests passed!")
