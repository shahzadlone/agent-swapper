#!/usr/bin/env python3
"""Run the Linux fixture inside an already delegated cgroup; never set one up."""

import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys


def nsdelegate_observation(mountinfo):
    """Report the mount's option without echoing untrusted mount text."""
    options = []
    for line in mountinfo.splitlines():
        left, separator, right = line.partition(" - ")
        prefix, suffix = left.split(), right.split()
        if separator and len(prefix) >= 5 and len(suffix) >= 3 and prefix[4] == "/sys/fs/cgroup" and suffix[0] == "cgroup2":
            options.append("nsdelegate" in suffix[2].split(","))
    if len(options) != 1:
        return "unknown"
    return "enabled" if options[0] else "not reported"


def main():
    if sys.platform != "linux" or os.geteuid() == 0:
        raise SystemExit("The fixture requires an unprivileged Linux process")
    if len(sys.argv) not in (2, 3, 4):
        raise SystemExit("Usage: run_delegated_custody_probe.py PATH_TO_PROBE [PATH_TO_TERMINAL_FIXTURE [PATH_TO_CORE_TEST]]")
    binary = Path(sys.argv[1]).resolve(strict=True)
    entries = [
        line.removeprefix("0::")
        for line in Path("/proc/self/cgroup").read_text().splitlines()
        if line.startswith("0::")
    ]
    if len(entries) != 1:
        raise SystemExit("No unique cgroup v2 membership")
    if not re.fullmatch(r"/system\.slice/aswp-custody-\d+-\d+\.service", entries[0]):
        raise SystemExit("Run only inside the dedicated CI systemd service; no automatic local setup")
    relative = PurePosixPath(entries[0])
    if not relative.is_absolute() or ".." in relative.parts or relative == PurePosixPath("/"):
        raise SystemExit("Refusing an ambiguous or root cgroup")
    parent = Path("/sys/fs/cgroup").joinpath(*relative.parts[1:])
    mount_option = nsdelegate_observation(Path("/proc/self/mountinfo").read_text())
    print(f"::notice title=Linux cgroup namespace delegation::nsdelegate {mount_option}", flush=True)
    # Run the journal cases first so their notices remain visible if the CI
    # annotation limit truncates later notices from the same step.
    if len(sys.argv) == 4:
        core_test = Path(sys.argv[3]).resolve(strict=True)
        env = os.environ.copy()
        env["ASWP_DELEGATED_CGROUP"] = str(parent)
        shim = Path(__file__).resolve().parents[1] / "target" / "debug" / "aswp"
        env["ASWP_TEST_CLI_SHIM"] = str(shim.resolve(strict=True))
        cases = [
            ("internal_guardian_checks_inherited_cgroup_capability", "Linux inherited cgroup capability"),
            ("internal_guardian_checks_same_user_cgroup_migration", "Linux cgroup migration"),
            ("internal_guardian_loss_preserves_unresolved_run_through_cleanup", "Linux internal guardian loss"),
            ("internal_guardian_cleans_up_on_incomplete_startup", "Linux internal guardian incomplete startup"),
            ("internal_guardian_reports_exit_after_cleanup", "Linux internal guardian exit"),
            ("internal_guardian_cleans_up_on_supervisor_channel_loss", "Linux internal guardian EOF"),
            ("internal_guardian_cleans_up_if_parent_disappears_before_retirement", "Linux internal guardian pre-retirement EOF"),
            ("real_journal_lease_survives_supervisor_loss_through_cgroup_cleanup", "Linux journal guardian"),
            ("supervisor_loss_before_go_keeps_journal_unresolved", "Linux pre-GO guardian"),
        ]
        unshare = shutil.which("unshare")
        if unshare:
            unshare = str(Path(unshare).resolve(strict=True))
            try:
                usable = subprocess.run([unshare, "--user", "--map-current-user", "--cgroup", "/bin/true"],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        check=False, timeout=10).returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                usable = False
        else:
            usable = False
        if usable:
            env["ASWP_TEST_UNSHARE"] = unshare
            cases.insert(0, ("internal_guardian_checks_namespaced_cgroup_migration", "Linux cgroup namespace migration"))
        else:
            print("::notice title=Linux cgroup namespace migration::not run; unprivileged namespace setup unavailable", flush=True)
        for name, notice in cases:
            result = subprocess.run([str(core_test), "--ignored", "--exact",
                                     f"store::linux_journal_guardian_tests::{name}",
                                     "--nocapture"], env=env, check=False, timeout=90,
                                    capture_output=True, text=True)
            sys.stdout.write(result.stdout)
            sys.stderr.write(result.stderr)
            sys.stdout.flush()
            sys.stderr.flush()
            if result.returncode:
                return result.returncode
            if f"::notice title={notice}::" not in result.stdout or "1 passed; 0 failed" not in result.stdout:
                raise SystemExit(f"delegated journal guardian test {name} did not actually run and pass")
    # Each Rust probe validates its delegated capabilities before any writes.
    result = subprocess.run([str(binary), str(parent)], check=False, timeout=90).returncode
    if result or len(sys.argv) == 2:
        return result
    terminal = Path(sys.argv[2]).resolve(strict=True)
    check = Path(__file__).with_name("check_linux_terminal_guardian.py")
    result = subprocess.run([sys.executable, str(check), str(terminal), "--cgroup-root", str(parent)],
                            check=False, timeout=90).returncode
    if result:
        return result
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
