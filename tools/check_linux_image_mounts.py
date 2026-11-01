#!/usr/bin/env python3
"""Installed-asset controls using owned tmpfs mounts in disposable hosted CI only."""
import hashlib
import json
import os
from pathlib import Path
import re
import select
import struct
import subprocess
import sys
import tempfile

CASES = {
    'protected': None,
    'config-nosuid-noexec': None,
    'config-executable': 'installed configuration is not mode 0644',
    'config-oversize': 'installed configuration exceeds 16 KiB',
    'config-retained': None,
    'config-replaced': 'installed configuration changed since admission began',
    'config-modified': 'installed configuration changed since admission began',
    'config-mode-changed': 'installed configuration changed since admission began',
    'manifest-protected': None,
    'manifest-protocol': 'installed manifest is invalid or incompatible',
    'manifest-user': 'installed manifest is invalid or incompatible',
    'manifest-unknown': 'installed manifest is invalid or incompatible',
    'manifest-duplicate': 'installed manifest is invalid or incompatible',
    'manifest-symlink': '(os error 40)',
    'config-digest': None,
    'config-digest-mismatch': 'installed asset digest mismatch',
    'image-digest': None,
    'image-digest-mismatch': 'installed asset digest mismatch',
    'image-retained': None,
    'image-replaced': 'installed image changed since admission began',
    'image-modified': 'installed image changed since admission began',
    'image-mode-changed': 'installed image changed since admission began',
    'bundle-protected': None,
    'bundle-guardian-mismatch': 'installed asset digest mismatch',
    'bundle-session-helper-mismatch': 'installed asset digest mismatch',
    'bundle-exec-shim-mismatch': 'installed asset digest mismatch',
    'bundle-template-mismatch': 'installed asset digest mismatch',
    'bundle-socket-mismatch': 'installed asset digest mismatch',
    'bundle-missing-helper': '(os error 2)',
    'bundle-guardian-replaced': 'installed image changed since admission began',
    'bundle-template-replaced': 'installed configuration changed since admission began',
    'bundle-manifest-replaced': 'installed configuration changed since admission began',
    'selection-protected': None,
    'selection-path': 'installed generation selector is invalid',
    'selection-unknown': 'installed generation selector is invalid',
    'selection-duplicate': 'installed generation selector is invalid',
    'selection-missing-generation': '(os error 2)',
    'selection-version': 'installed manifest is invalid or incompatible',
    'selection-selector-replaced': 'installed configuration changed since admission began',
    'selection-manifest-replaced': 'installed configuration changed since admission began',
    'selection-guardian-modified': 'installed image changed since admission began',
    'selection-generation-switch': 'installed configuration changed since admission began',
    'nosuid': 'image filesystem is noexec or nosuid',
    'noexec': 'image filesystem is noexec or nosuid',
    'capability': 'image has file capabilities',
    'symlink': '(os error 40)',
    'fifo': 'installed file is not a root-owned protected regular file',
    'writable': 'installed file is not a root-owned protected regular file',
    'user-owned': 'installed file is not a root-owned protected regular file',
}
PRESERVE = 'GITHUB_ACTIONS,RUNNER_ENVIRONMENT,GITHUB_RUN_ID,GITHUB_RUN_ATTEMPT,ASWP_CI_IMAGE_MOUNTS,ASWP_CI_IMAGE_PACKAGE_VERSION'
BUNDLE_FILES = {
    'guardian': ('guardian', 'guardian_sha256', 0o755),
    'session-helper': ('session-helper', 'session_helper_sha256', 0o755),
    'exec-shim': ('exec-shim', 'exec_shim_sha256', 0o755),
    'template': ('fixture@.service', 'service_template_sha256', 0o644),
    'socket': ('fixture.socket', 'socket_unit_sha256', 0o644),
}


GENERATION = '00112233445566778899aabbccddeeff'
NEXT_GENERATION = '112233445566778899aabbccddeeff00'


def write_generation(base, generation, version, uid, gid):
    directory = base / generation
    directory.mkdir(mode=0o755)
    document = dict(schema=1, protocol=1, version=version, generation=generation, user=uid, group=gid)
    for name, (filename, field, mode) in BUNDLE_FILES.items():
        payload = ('owned inert ' + name + '\n').encode()
        document[field] = hashlib.sha256(payload).hexdigest()
        asset = directory / filename
        asset.write_bytes(payload)
        asset.chmod(mode)
    manifest = base / (generation + '.json')
    manifest.write_text(json.dumps(document))
    manifest.chmod(0o644)


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
    # A separate namespace may still propagate mounts to a shared peer. The
    # outer command requests recursive private propagation; verify that fact
    # independently before creating a fixture, including direct --inside use.
    mounts = Path('/proc/self/mountinfo').read_text().splitlines()
    require(bool(mounts) and all(' - ' in line for line in mounts),
            'mount propagation metadata unavailable')
    require(not any(field.startswith('shared:') for line in mounts
                    for field in line.split(' - ', 1)[0].split()[6:]),
            'fixture mount namespace still has shared propagation')


def identity(uid, gid):
    uid, gid = int(uid), int(gid)
    require(0 < uid < 2**31 and 0 < gid < 2**31, 'ordinary fixture identity required')
    return uid, gid


def retained_asset_control(command, image, case):
    # The child drops root before exec. Mutate only this namespace's owned tmpfs
    # file after the ordinary observer has retained its original descriptor.
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as child:
        try:
            ready, _, _ = select.select([child.stdout], [], [], 5)
            require(bool(ready) and child.stdout.readline(128) == b'installed-asset: retained\n',
                    'retained asset observer did not reach its hold')
            if case.startswith('bundle-'):
                selected = {'bundle-guardian-replaced': 'guardian',
                            'bundle-template-replaced': 'fixture@.service',
                            'bundle-manifest-replaced': 'image'}[case]
                image = image.with_name(selected)
            elif case.startswith('selection-'):
                selected = {'selection-selector-replaced': 'active.json',
                            'selection-manifest-replaced': GENERATION + '.json',
                            'selection-guardian-modified': GENERATION + '/guardian',
                            'selection-generation-switch': 'active.json'}[case]
                image = image.parent / selected
            if case.endswith('-replaced'):
                replacement = image.with_name('replacement')
                replacement.write_bytes(image.read_bytes())
                replacement.chmod(image.stat().st_mode & 0o7777)
                require(replacement.stat().st_ino != image.stat().st_ino,
                        'replacement control needs a distinct inode')
                replacement.replace(image)
            elif case in ('config-modified', 'image-modified', 'selection-guardian-modified'):
                image.write_bytes(b'changed owned configuration\n')
            elif case == 'selection-generation-switch':
                image.write_text(json.dumps(dict(schema=1, generation=NEXT_GENERATION)))
            elif case in ('config-mode-changed', 'image-mode-changed'):
                image.chmod(0o664)
            stdout, stderr = child.communicate(b'R', timeout=5)
            return subprocess.CompletedProcess(command, child.returncode, stdout, stderr)
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)


def mounted_case(case, binary, uid, gid):
    private_namespace()
    require(case in CASES, 'unknown image fixture case')
    version = os.environ.get('ASWP_CI_IMAGE_PACKAGE_VERSION', '')
    if case.startswith(('manifest-', 'bundle-', 'selection-')):
        require(re.fullmatch(r'[0-9][A-Za-z0-9.+-]{0,127}', version), 'invalid fixture package version')
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
        # These inert bytes are never executed. The probe checks metadata/content.
        image.write_bytes(b'owned image-policy fixture\n')
        image.chmod(0o644 if case.startswith(('config-', 'manifest-', 'bundle-')) and case != 'config-executable' else 0o755)
        if case.startswith('selection-'):
            write_generation(base, GENERATION, 'incompatible' if case == 'selection-version' else version, uid, gid)
            document = dict(schema=1, generation=GENERATION)
            if case == 'selection-path':
                document['generation'] = '../outside'
            elif case == 'selection-unknown':
                document['unexpected'] = 'selector-private-canary'
            elif case == 'selection-missing-generation':
                document['generation'] = NEXT_GENERATION
            elif case == 'selection-generation-switch':
                write_generation(base, NEXT_GENERATION, version, uid, gid)
            contents = json.dumps(document)
            if case == 'selection-duplicate':
                contents = '{"schema":1,' + contents[1:]
            selector = base / 'active.json'
            selector.write_text(contents)
            selector.chmod(0o644)
        if case.startswith(('manifest-', 'bundle-')):
            document = dict(schema=1, protocol=1, version=version, generation='00112233445566778899aabbccddeeff',
                            user=uid, group=gid, guardian_sha256='a'*64, session_helper_sha256='b'*64,
                            exec_shim_sha256='c'*64, service_template_sha256='d'*64, socket_unit_sha256='e'*64)
            if case == 'manifest-protocol':
                document['protocol'] = 2
            elif case == 'manifest-user':
                document['user'] = uid + 1
            elif case == 'manifest-unknown':
                document['unexpected'] = 'manifest-private-canary'
            if case.startswith('bundle-'):
                for name, (filename, field, mode) in BUNDLE_FILES.items():
                    # Different bytes and hashes catch accidentally crossed
                    # field/role mappings. None of these files is executable code.
                    payload = ('owned inert ' + name + '\n').encode()
                    document[field] = hashlib.sha256(payload).hexdigest()
                    asset = base / filename
                    asset.write_bytes(payload if case != f'bundle-{name}-mismatch' else b'mismatched bytes\n')
                    asset.chmod(mode)
                if case == 'bundle-missing-helper':
                    (base / 'session-helper').unlink()
            contents = json.dumps(document)
            if case == 'manifest-duplicate':
                contents = '{"schema":1,' + contents[1:]
            image.write_text(contents)
        if case == 'config-oversize':
            image.write_bytes(b'x' * (16 * 1024 + 1))
        if case in ('config-digest-mismatch', 'image-digest-mismatch'):
            image.write_bytes(b'different owned asset\n')
        if case == 'capability':
            # Linux VFS_CAP_REVISION_2, effective CAP_NET_BIND_SERVICE. The file
            # remains root-owned and is never executed, including by the probe.
            os.setxattr(image, 'security.capability', struct.pack('<5I', 0x02000001, 1 << 10, 0, 0, 0))
        elif case in ('symlink', 'manifest-symlink'):
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
        if case.startswith('manifest-'):
            role = '--manifest-probe'
        if case.startswith('bundle-'):
            role = '--bundle-probe'
        if case.startswith('selection-'):
            role = '--selection-probe'
        retained = case in ('config-retained', 'config-replaced', 'config-modified', 'config-mode-changed',
                           'image-retained', 'image-replaced', 'image-modified', 'image-mode-changed',
                           'bundle-guardian-replaced', 'bundle-template-replaced', 'bundle-manifest-replaced',
                           'selection-selector-replaced', 'selection-manifest-replaced',
                           'selection-guardian-modified', 'selection-generation-switch')
        if retained:
            role = ('--selection-recheck-probe' if case.startswith('selection-') else
                    '--bundle-recheck-probe' if case.startswith('bundle-') else
                    '--config-recheck-probe' if case.startswith('config-') else '--image-recheck-probe')
        elif case.startswith('config-digest'):
            role = '--config-digest-probe'
        elif case.startswith('image-digest'):
            role = '--image-digest-probe'
        command = ['/usr/bin/python3', '-I', '-S', script, role, binary, str(image), str(uid), str(gid)]
        result = (retained_asset_control(command, image, case) if retained else
                  subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=5))
        expected = CASES[case]
        if expected is None:
            require(result.returncode == 0 and result.stdout == b'installed-asset: accepted\n'
                    and not result.stderr, 'protected image control was refused: ' + result.stderr.decode(errors='replace'))
        else:
            require(result.returncode == 125 and not result.stdout
                    and expected.encode() in result.stderr,
                    f'{case}: image did not refuse at intended check: ' + result.stderr.decode(errors='replace'))
            if expected in ('installed manifest is invalid or incompatible', 'installed generation selector is invalid'):
                require(result.stderr == ('installed-asset: ' + expected + '\n').encode(),
                        'installed data refusal echoed untrusted content')
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
    modes = {'--config-probe': '--config', '--config-recheck-probe': '--config-recheck', '--manifest-probe': '--manifest',
             '--config-digest-probe': '--config-digest', '--image-digest-probe': '--image-digest',
             '--image-recheck-probe': '--image-recheck', '--bundle-probe': '--bundle',
             '--bundle-recheck-probe': '--bundle-recheck', '--selection-probe': '--selection',
             '--selection-recheck-probe': '--selection-recheck'}
    if len(args) == 5 and args[0] in ('--inside', '--probe', *modes):
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
        probe_args = [first, modes[role], second] if role in modes else [first, second]
        os.execve(first, probe_args, {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    require(len(args) == 1 and os.geteuid() != 0, 'ordinary hosted fixture runner required')
    binary = Path(args[0])
    require(binary.is_absolute() and binary.is_file() and not binary.is_symlink(), 'invalid fixture probe')
    version = subprocess.run([str(binary), '--manifest-version'], stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, timeout=5, check=True)
    require(not version.stderr and re.fullmatch(r'[0-9][A-Za-z0-9.+-]{0,127}\n', version.stdout),
            'fixture probe returned an invalid package version')
    environment = dict(os.environ, ASWP_CI_IMAGE_PACKAGE_VERSION=version.stdout.strip())
    for case in CASES:
        subprocess.run(['sudo', '-n', '--preserve-env=' + PRESERVE, '/usr/bin/timeout', '--kill-after=3s',
                        '20s', '/usr/bin/unshare', '--mount', '--propagation', 'private', '--fork',
                        '--kill-child', '/usr/bin/python3', '-I', '-S', str(Path(__file__).resolve()),
                        '--inside', case, str(binary), str(os.getuid()), str(os.getgid())],
                       stdin=subprocess.DEVNULL, env=environment, check=True, timeout=25)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        diagnostic = json.dumps(str(error)[-2000:], ensure_ascii=True)[1:-1].replace('%', '%25')
        print('::error title=Linux image policy::' + diagnostic, flush=True)
        sys.exit(1)
