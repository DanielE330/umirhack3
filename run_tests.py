"""Единый запускатор всех автоматических тестов платформы HoneyForge.
Запускает тесты всех подсистем (Agent, Center, Orchestrator, HoneyMind).
"""
import sys
import subprocess
from pathlib import Path

SUITES = [
    ("HoneyMind AI/ML & Analytics", "honeymind/tests", ["honeymind"]),
    ("Agent & Deception Traps", "agent/tests", ["agent"]),
    ("Center Backend & Auth/2FA/RBAC", "backend/center/tests", ["backend/center"]),
    ("Orchestrator & Proxmox Management", "backend/orchestrator/tests", ["backend/orchestrator"]),
]

def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    root = Path(__file__).resolve().parent
    total_passed = 0
    all_ok = True

    print("=" * 70)
    print("HoneyForge Automated Test Suite Verification (100% Green)")
    print("=" * 70)

    for title, test_path, pythonpaths in SUITES:
        print(f"\n>> Running: {title} ({test_path})...")
        env = dict(sys.modules.get("os", __import__("os")).environ)
        extra_paths = [str((root / p).resolve()) for p in pythonpaths] + [str(root.resolve())]
        env["PYTHONPATH"] = ";".join(extra_paths) if sys.platform == "win32" else ":".join(extra_paths)

        cmd = [sys.executable, "-m", "pytest", test_path, "--disable-warnings"]
        res = subprocess.run(cmd, cwd=str(root), env=env, capture_output=True, text=True)

        output = res.stdout.strip()
        lines = [l for l in output.splitlines() if "passed" in l or "failed" in l or "error" in l]
        summary = lines[-1] if lines else "No summary line"
        print(f"  {summary}")

        if res.returncode != 0:
            all_ok = False
            if res.stderr:
                print(f"  STDERR: {res.stderr[:300]}")
        else:
            # Парсим количество пройденных тестов: '=== 149 passed, ... ==='
            import re
            m = re.search(r"(\d+)\s+passed", summary)
            if m:
                total_passed += int(m.group(1))

    print("\n" + "=" * 70)
    if all_ok:
        print(f"SUCCESS: All {total_passed} tests PASSED across all microservices!")
        print("Platform status: 100% Green, zero failures.")
        print("=" * 70)
        return 0
    else:
        print("FAILURE: Some tests failed!")
        print("=" * 70)
        return 1

if __name__ == "__main__":
    sys.exit(main())
