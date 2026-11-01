#!/usr/bin/env python3
"""Installed-asset controls using owned tmpfs mounts in disposable hosted CI only."""
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

CASES = {
    'protected': None,
    'config-nosuid-noexec': None,
    'config-executable': 'installed configuration is not mode 0644',
    'config-oversize': 'installed configuration exceeds 16 KiB',
    'nosuid': 'image filesystem is noexec or nosuid',
    'noexec': 'image filesystem is noexec or nosuid',
    'capability': 'image has file capabilities',
    'symlink': '(os error 40)',
    'fifo': 'installed file is not a root-owned protected regular file',
    'writable': 'installed file is not a root-owned protected regular file',
    'user-owned': 'installed file is not a root-owned protected regular file',
}
PRESERVE = 'GITHUB_ACTIONS,RUNNER_ENVIRONMENT,GITHUB_RUN_ID,GITHUB_RUN_ATTEMPT,ASWP_CI_IMAGE_MOUNTS'


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def gate():
    require(sys.platform == 'linux' and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and os.environ.get('ASWP_CI_IMAGE_MOUNTS') == '1'
            and re.fullmatch(r'[0-9]{1,24}', os.environ.get('GITHUB_RUN_ID', ''))
            and re.fullmatch(r'[0-9]{1,8}', os.environ.get('GITHUB_RUN_ATTEMPT', '')),
            'image mounts require an opted-in disposable hosted runner')


def private_namespace():
    require(os.geteuid() == 0
            and os.readlink('/proc/self/ns/mnt') != os.readlink('/proc/1/ns/mnt'),
            'fixture requires its own root mount namespace')


def identity(uid, gid):
    uid, gid = int(uid), int(gid)
    require(0 < uid < 2**31 and 0 < gid < 2**31, 'ordinary fixture identity required')
    return uid, gid


def mounted_case(case, binary, uid, gid):
    private_namespace()
    require(case in CASES, 'unknown image fixture case')
    base = Path(tempfile.mkdtemp(prefix='aswp-image-mount-', dir='/run'))
    original = base.stat(follow_symlinks=False)
    mounted = False
    try:
        options = 'rw,nodev,exec,suid,mode=0755,size=1m'
        if case in ('nosuid', 'noexec'):
            options += ',' + case
        elif case == 'config-nosuid-noexec':
            options += ',nosuid,noexec'
        subprocess.run(['/usr/bin/mount', '-t', 'tmpfs', '-o', options, 'aswp-image-fixture', str(base)],
                       stdin=subprocess.DEVNULL, check=True, capture_output=True, timeout=5)
        mounted = True
        image = base / 'image'
        # These inert bytes are never executed. The probe only opens metadata.
        image.write_bytes(b'owned image-policy fixture\n')
        image.chmod(0o644 if case.startswith('config-') and case != 'config-executable' else 0o755)
        if case == 'config-oversize':
            image.write_bytes(b'x' * (16 * 1024 + 1))
        if case == 'capability':
            # Linux VFS_CAP_REVISION_2, effective CAP_NET_BIND_SERVICE. The file
            # remains root-owned and is never executed, including by the probe.
            os.setxattr(image, 'security.capability', struct.pack('<5I', 0x02000001, 1 << 10, 0, 0, 0))
        elif case == 'symlink':
            image.rename(base / 'target')
            image.symlink_to('target')
        elif case == 'fifo':
            image.unlink()
            os.mkfifo(image, 0o755)
        elif case == 'writable':
            image.chmod(0o775)
        elif case == 'user-owned':
            os.chown(image, uid, gid)
        script = str(Path(__file__).resolve())
        role = '--config-probe' if case.startswith('config-') else '--probe'
        result = subprocess.run(['/usr/bin/python3', '-I', '-S', script, role, binary,
                                 str(image), str(uid), str(gid)], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=5)
        expected = CASES[case]
        if expected is None:
            require(result.returncode == 0 and result.stdout == b'installed-asset: accepted\n'
                    and not result.stderr, 'protected image control was refused: ' + result.stderr.decode(errors='replace'))
        else:
            require(result.returncode == 125 and not result.stdout
                    and expected.encode() in result.stderr,
                    f'{case}: image did not refuse at intended check: ' + result.stderr.decode(errors='replace'))
        print(f'::notice title=Linux image policy::{case}: pass; probe ran as ordinary user and never executed the image', flush=True)
    finally:
        if mounted:
            # A failed unmount stops cleanup; never recursively delete a mount.
            subprocess.run(['/usr/bin/umount', str(base)], stdin=subprocess.DEVNULL,
                           check=True, capture_output=True, timeout=5)
        current = base.stat(follow_symlinks=False)
        require((current.st_dev, current.st_ino, current.st_uid)
                == (original.st_dev, original.st_ino, 0), 'owned fixture directory changed')
        base.rmdir()


def main():
    gate()
    args = sys.argv[1:]
    if len(args) == 5 and args[0] in ('--inside', '--probe', '--config-probe'):
        private_namespace()
        role, first, second, uid, gid = args
        uid, gid = identity(uid, gid)
        if role == '--inside':
            mounted_case(first, second, uid, gid)
            return
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
        require(os.getuid() == os.geteuid() == uid and os.getgid() == os.getegid() == gid,
                'probe failed to drop its root identity')
        probe_args = [first, '--config', second] if role == '--config-probe' else [first, second]
        os.execve(first, probe_args, {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    require(len(args) == 1 and os.geteuid() != 0, 'ordinary hosted fixture runner required')
    binary = Path(args[0])
    require(binary.is_absolute() and binary.is_file() and not binary.is_symlink(), 'invalid fixture probe')
    for case in CASES:
        subprocess.run(['sudo', '-n', '--preserve-env=' + PRESERVE, '/usr/bin/timeout', '--kill-after=3s',
                        '20s', '/usr/bin/unshare', '--mount', '--propagation', 'private', '--fork',
                        '--kill-child', '/usr/bin/python3', '-I', '-S', str(Path(__file__).resolve()),
                        '--inside', case, str(binary), str(os.getuid()), str(os.getgid())],
                       stdin=subprocess.DEVNULL, check=True, timeout=25)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        diagnostic = json.dumps(str(error)[-2000:], ensure_ascii=True)[1:-1].replace('%', '%25')
        print('::error title=Linux image policy::' + diagnostic, flush=True)
        sys.exit(1)
