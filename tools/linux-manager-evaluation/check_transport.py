"""Check the read-only observer and prove environment overrides are ignored."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--require-manager', action='store_true')
    args = parser.parse_args()
    binary = str(args.binary.resolve(strict=True))
    with tempfile.TemporaryDirectory(prefix='aswp-bus-override-') as temp:
        endpoint = str(Path(temp) / 'fake-bus')
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(endpoint)
            listener.listen(4)
            listener.setblocking(False)
            env = os.environ.copy()
            env['DBUS_SYSTEM_BUS_ADDRESS'] = 'unix:path=' + endpoint
            result = subprocess.run([binary], env=env, stdin=subprocess.DEVNULL,
                                    capture_output=True, text=True, encoding='utf-8',
                                    errors='replace', timeout=12, check=False)
            try:
                connection, _ = listener.accept()
            except BlockingIOError:
                pass
            else:
                connection.close()
                raise RuntimeError('observer connected to the untrusted environment address')
        if result.returncode:
            if args.require_manager or result.returncode != 125:
                raise RuntimeError('manager inspection failed: ' + result.stderr[-2000:])
            # A local unavailable observation is not hosted positive evidence.
            print('Manager unavailable/refused locally; environment listener received no connection.')
            print(result.stderr[-2000:].strip())
        else:
            if len(result.stdout) > 8192:
                raise RuntimeError('manager report exceeds bounds')
            report = json.loads(result.stdout)
            if not (report['dbus_override_ignored'] is True and report['peer_uid'] == 0
                    and report['manager_uid'] == 0 and report['manager_pid'] == 1):
                raise RuntimeError('manager identity or environment-override check disagrees')
            text = json.dumps(report, sort_keys=True).replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
            print('::notice title=Linux manager transport baseline::' + text)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # This provider-free fixture only reports bounded, escaped metadata.
        message = json.dumps(str(error)[-2000:], ensure_ascii=True)[1:-1].replace('%', '%25')
        print('::error title=Linux manager transport baseline::' + message, flush=True)
        sys.exit(1)
