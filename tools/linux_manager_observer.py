"""Bounded reader for the owned, provider-free Rust manager observer."""
import json
import os
import selectors
import subprocess
import tempfile
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class Observer:
    def __init__(self, binary, unit, uid, pid, invocation):
        self.errors = tempfile.TemporaryFile()
        self.pending = bytearray()
        try:
            self.process = subprocess.Popen(
                [binary, '--watch', unit + '.service', str(uid), str(pid), invocation],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=self.errors,
                bufsize=0, close_fds=True)
        except BaseException:
            self.errors.close()
            raise

    def receive(self, timeout):
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            while b'\n' not in self.pending:
                remaining = deadline - time.monotonic()
                require(remaining > 0 and selector.select(remaining), 'Rust observer report deadline exceeded')
                data = os.read(self.process.stdout.fileno(), 8193)
                if not data:
                    self.errors.seek(0)
                    detail = self.errors.read(2000).decode('utf-8', errors='replace')
                    raise RuntimeError('Rust observer closed before a complete report: ' + detail)
                self.pending.extend(data)
                # At most two complete records may arrive together. Each line
                # still has its own bound; no unbounded read or readline call.
                require(len(self.pending) <= 16386, 'Rust observer output exceeds bounds')
                if b'\n' not in self.pending:
                    require(len(self.pending) <= 8192, 'Rust observer record exceeds bounds')
        line, _, rest = self.pending.partition(b'\n')
        self.pending = bytearray(rest)
        require(len(line) <= 8192, 'Rust observer record exceeds bounds')
        return json.loads(line)

    def finish(self):
        output, _ = self.process.communicate(timeout=3)
        require(self.process.returncode == 0 and not self.pending and not output,
                'Rust observer failed or produced unexpected trailing output')

    def close(self):
        try:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait(timeout=3)
        finally:
            self.process.stdout.close()
            self.errors.close()


def check_bound(report, unit, uid, pid, invocation, device, inode):
    require(report['phase'] == 'bound' and report['retirement'] is None
            and report['peer_uid'] == 0 and report['manager_uid'] == 0 and report['manager_pid'] == 1,
            'Rust observer did not bind an authenticated live unit')
    fact = report['unit']
    kernel = fact['kernel']
    require(fact['unit'] == unit + '.service' and fact['invocation'] == invocation
            and fact['pid'] == pid and fact['user'] == uid
            and fact['control_group'] == '/system.slice/' + unit + '.service'
            and fact['delegate'] is False and fact['kill_mode'] == 'control-group'
            and kernel['device'] == device and kernel['inode'] == inode
            and kernel['populated'] is True and kernel['main_pidfd_live'] is True
            and kernel['migration_controls_refused'] is True,
            'Rust observer binding disagrees with the live fixture')


def check_retired(report, bound):
    require(bound['phase'] == 'bound' and bound['retirement'] is None,
            'retirement requires an earlier bound observation')
    require(report['phase'] == 'retired' and report['unit'] == bound['unit']
            and report['peer_uid'] == bound['peer_uid'] == 0
            and report['manager_uid'] == bound['manager_uid'] == 0
            and report['manager_pid'] == bound['manager_pid'] == 1,
            'Rust retirement changed the original binding')
    retired, kernel = report['retirement'], bound['unit']['kernel']
    require(retired['device'] == kernel['device'] and retired['inode'] == kernel['inode']
            and retired['original_directory_removed'] is True and retired['main_pidfd_exited'] is True,
            'Rust retirement did not observe the original kernel scope and main process')
