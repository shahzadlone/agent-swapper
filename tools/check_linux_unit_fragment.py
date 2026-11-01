#!/usr/bin/env python3
"""Measure systemd's vendor-unit FragmentPath; never starts a service."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

_spec = importlib.util.spec_from_file_location(
    'aswp_fragment_activation', Path(__file__).with_name('check_linux_socket_activation.py'))
_activation = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_activation)
require = _activation.require


DIRECTORIES = {'vendor': Path('/usr/lib/systemd/system'), 'generated': Path('/etc/systemd/system')}


def expected_fragment(fragment, name, kind):
    return fragment == str(DIRECTORIES[kind] / name) or (
        kind == 'vendor' and fragment == f'/lib/systemd/system/{name}')


def administer(kind):
    prefix = _activation.fixture_prefix().replace('aswp-activation-', 'aswp-fragment-', 1)
    require(os.geteuid() == 0, 'fragment measurement requires its disposable administrator')
    uid, gid = _activation.ordinary_ids(os.environ.get('SUDO_UID', ''), os.environ.get('SUDO_GID', ''))
    name = prefix + '-' + kind + '.service'
    path = DIRECTORIES[kind] / name
    for parent in reversed(path.parents):
        metadata = parent.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0
                and metadata.st_mode & 0o022 == 0, 'measurement unit ancestry is not protected')
    require(not os.path.lexists(path), 'fragment measurement unit already exists')
    require(_activation.unit_properties(name, ('LoadState',)) == {'LoadState': 'not-found'},
            'fragment measurement name already resolves')
    # There is no install section, dependency or socket. Manual activation is
    # explicitly refused even if an unrelated process asks to start this unit.
    contents = (f'[Unit]\nDescription=AgentSwapper path measurement\nRefuseManualStart=yes\n'
                f'[Service]\nType=oneshot\nUser={uid}\nGroup={gid}\nExecStart=/usr/bin/false\n')
    created = []
    try:
        _activation.create_owned_file(path, contents.encode(), 0o644, created)
        _activation.verify_config(path, contents)
        _activation.systemctl('daemon-reload')
        fields = _activation.unit_properties(name, (
            'LoadState', 'FragmentPath', 'DropInPaths', 'NeedDaemonReload', 'ActiveState', 'MainPID'))
        require(fields['LoadState'] == 'loaded' and fields['ActiveState'] == 'inactive'
                and fields['MainPID'] == '0' and fields['DropInPaths'] == ''
                and fields['NeedDaemonReload'] == 'no', 'measurement unit is not an unchanged inactive unit')
        require(expected_fragment(fields['FragmentPath'], name, kind), 'unexpected fragment spelling')
        reported = Path(fields['FragmentPath']).stat()
        require((reported.st_dev, reported.st_ino) == created[0][1:],
                'reported fragment does not name the exclusively created inode')
        alias = Path('/lib').lstat()
        print('::notice title=Linux unit fragment::' + json.dumps({
            'kind': kind,
            'created': str(path), 'reported': fields['FragmentPath'], 'same_inode': True,
            'lib_is_root_owned': alias.st_uid == 0, 'lib_is_symlink': stat.S_ISLNK(alias.st_mode),
            'lib_target': os.readlink('/lib') if stat.S_ISLNK(alias.st_mode) else None,
            'service_started': False}, sort_keys=True), flush=True)
    finally:
        # This unit was never started. Remove only the original exclusive
        # creation, then make the system manager forget its loaded definition.
        _activation.rollback_created(created)
        _activation.systemctl('daemon-reload')
        require(not os.path.lexists(path), 'owned measurement file survived cleanup')
        require(_activation.unit_properties(name, ('LoadState',)) == {'LoadState': 'not-found'},
                'owned measurement unit survived cleanup')


def main():
    args = sys.argv[1:]
    require(args in ([], ['--admin', 'vendor'], ['--admin', 'generated']),
            'unexpected fragment measurement arguments')
    _activation.fixture_prefix()
    if args:
        administer(args[1])
    else:
        require(os.geteuid() != 0, 'fragment measurement requires an ordinary runner')
        for kind in DIRECTORIES:
            subprocess.run(['sudo', '-n', '--preserve-env=' + _activation.PRESERVE,
                            '/usr/bin/timeout', '--kill-after=3s', '45s', '/usr/bin/python3', '-I', '-B', '-S',
                            str(Path(__file__).resolve()), '--admin', kind], check=True, timeout=50)


if __name__ == '__main__':
    main()
