#!/usr/bin/env python3
"""E2E tests for the `teleproxy check` diagnostic subcommand.

Tests exit codes, output format, and individual checks.
Runs inside a Docker container with the teleproxy binary available.
"""
import os
import re
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


# ── DC override ID validation ────────────────────────────────────

print("\n=== DC override ID validation ===")

# 11. CDN DCs (201-299) are valid override targets → exit 0
code, out, err = run_check("--direct", "-S", secret,
                           "--dc-override", "203:127.0.0.1:1")
check("CLI override for CDN DC 203 accepted",
      code == 0,
      f"got exit {code}\nstdout: {out[:300]}\nstderr: {err[:300]}")

# 12. Identifiers outside the production/CDN ranges are rejected → exit 2
code, out, err = run_check("--direct", "-S", secret,
                           "--dc-override", "300:127.0.0.1:1")
check("CLI override above CDN range rejected",
      code == 2 and "201-299" in err,
      f"got exit {code}\nstderr: {err[:300]}")

# 13. The same range applies to TOML dc_override
with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
    f.write(
        f'direct = true\n\n[[secret]]\nkey = "{secret}"\n\n'
        '[[dc_override]]\ndc = 203\nhost = "127.0.0.1"\nport = 1\n'
    )
    toml_cdn_path = f.name
try:
    code, out, err = run_check("--config", toml_cdn_path)
    check("TOML override for CDN DC 203 accepted",
          code == 0,
          f"got exit {code}\nstdout: {out[:300]}\nstderr: {err[:300]}")
finally:
    os.unlink(toml_cdn_path)

# 14. And TOML rejects ids outside it
with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
    f.write(
        f'direct = true\n\n[[secret]]\nkey = "{secret}"\n\n'
        '[[dc_override]]\ndc = 300\nhost = "127.0.0.1"\nport = 1\n'
    )
    toml_bad_path = f.name
try:
    code, out, err = run_check("--config", toml_bad_path)
    check("TOML override above CDN range rejected",
          code == 2 and "201-299" in err,
          f"got exit {code}\nstderr: {err[:300]}")
finally:
    os.unlink(toml_bad_path)


# ── NTP test ─────────────────────────────────────────────────────

print("\n=== NTP clock test ===")

# 15. Clock sync check runs
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

# 16. Valid domain probe (google.com is universally accessible)
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

# 17. Unreachable domain → FAIL
code, out, err = run_check("--direct", "-S", secret, "-D", "nonexistent.invalid")
check("unreachable domain → exit 1",
      code == 1,
      f"got exit {code}")
tls_lines = [l for l in out.split("\n") if "TLS nonexistent" in l]
check("TLS nonexistent.invalid → FAIL",
      len(tls_lines) > 0 and "FAIL" in tls_lines[0],
      f"lines: {tls_lines}")

# 18. SNI mismatch warning (domain IP != container IP)
code, out, err = run_check("--direct", "-S", secret, "-D", "google.com")
sni_lines = [l for l in out.split("\n") if "SNI" in l]
check("SNI check present for domain",
      len(sni_lines) > 0,
      f"output: {out[:300]}")


# ── Output format tests ──────────────────────────────────────────

print("\n=== Output format tests ===")

code, out, err = run_check("--direct", "-S", secret, "-D", "google.com")

# 19. Summary line present
lines = out.strip().split("\n")
last_line = lines[-1].strip() if lines else ""
check("summary line present",
      re.match(r"\d+ passed, \d+ failed, \d+ warning", last_line),
      f"last line: '{last_line}'")

# 20. Config summary
check("config summary in output",
      "mode: direct" in out,
      f"output: {out[:200]}")

# 21. Header line
check("header line present",
      "teleproxy check" in out,
      f"output: {out[:100]}")

# 22. Dot alignment (each result line has dots)
result_lines = [l for l in lines if ".." in l and ("OK" in l or "FAIL" in l or "WARN" in l or "SKIP" in l)]
check("result lines have dot alignment",
      len(result_lines) >= 7,
      f"found {len(result_lines)} aligned result lines")


# ── Summary ──────────────────────────────────────────────────────

print(f"\n{'=' * 40}")
print(f"Results: {passed} passed, {failed} failed")

if failed > 0:
    sys.exit(1)
print("All tests passed!")
