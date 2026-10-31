"""Reader, generation-binding and owned-process cleanup regressions."""
from copy import deepcopy
import io
import socket
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from linux_manager_observer import Observer, check_bound, check_retired


class ObserverTests(unittest.TestCase):
    def reports(self):
        bound = {'phase': 'bound', 'retirement': None, 'peer_uid': 0,
                 'manager_uid': 0, 'manager_pid': 1,
                 'unit': {'unit': 'aswp-managed-test.service', 'invocation': 'a' * 32,
                          'pid': 42, 'user': 1000, 'control_group': '/system.slice/aswp-managed-test.service',
                          'delegate': False, 'kill_mode': 'control-group',
                          'kernel': {'device': 11, 'inode': 22, 'populated': True,
                                     'main_pidfd_live': True, 'migration_controls_refused': True}}}
        retired = {**deepcopy(bound), 'phase': 'retired',
                   'retirement': {'device': 11, 'inode': 22, 'original_directory_removed': True,
                                  'main_pidfd_exited': True}}
        return bound, retired

    def test_retirement_requires_the_same_prior_binding_and_both_kernel_facts(self):
        bound, retired = self.reports()
        check_bound(bound, 'aswp-managed-test', 1000, 42, 'a' * 32, 11, 22)
        check_retired(retired, bound)
        for field, value in [('inode', 23), ('device', 12), ('original_directory_removed', False),
                             ('main_pidfd_exited', False)]:
            bad = deepcopy(retired)
            bad['retirement'][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                check_retired(bad, bound)
        replaced = deepcopy(retired)
        replaced['unit']['invocation'] = 'b' * 32
        with self.assertRaises(RuntimeError):
            check_retired(replaced, bound)
        with self.assertRaises(RuntimeError):
            check_retired(retired, {**bound, 'phase': 'snapshot'})
        with self.assertRaises(RuntimeError):
            check_bound(bound, 'aswp-managed-test', 1000, 42, 'b' * 32, 11, 22)

    def reader(self, stream):
        observer = Observer.__new__(Observer)
        observer.process = SimpleNamespace(stdout=stream)
        observer.pending = bytearray()
        observer.errors = io.BytesIO(b'bounded fixture diagnostic')
        return observer

    def test_coalesced_records_preserve_the_second_observation(self):
        incoming, outgoing = socket.socketpair()
        with incoming, outgoing, incoming.makefile('rb', buffering=0) as stream:
            observer = self.reader(stream)
            outgoing.sendall(b'{"phase":"bound"}\n{"phase":"retired"}\n')
            self.assertEqual(observer.receive(1), {'phase': 'bound'})
            self.assertEqual(observer.receive(1), {'phase': 'retired'})
            self.assertFalse(observer.pending)

    def test_oversized_incomplete_and_stalled_records_fail(self):
        for payload in (b'x' * 8193, b'{"incomplete":true}', b''):
            incoming, outgoing = socket.socketpair()
            with self.subTest(size=len(payload)), incoming, outgoing, incoming.makefile('rb', buffering=0) as stream:
                observer = self.reader(stream)
                outgoing.sendall(payload)
                outgoing.shutdown(socket.SHUT_WR)
                with self.assertRaises(RuntimeError):
                    observer.receive(1)
        incoming, outgoing = socket.socketpair()
        with incoming, outgoing, incoming.makefile('rb', buffering=0) as stream:
            with self.assertRaisesRegex(RuntimeError, 'deadline'):
                self.reader(stream).receive(0.02)

    def test_cleanup_reaps_the_owned_probe_after_incomplete_observation(self):
        spawn = subprocess.Popen
        def sleeper(_args, **kwargs):
            return spawn([sys.executable, '-c', 'import time; time.sleep(30)'], env={}, **kwargs)
        with patch('linux_manager_observer.subprocess.Popen', side_effect=sleeper):
            observer = Observer('/fixture/observer', 'aswp-managed-test', 1000, 42, 'a' * 32)
        try:
            self.assertIsNone(observer.process.poll())
            observer.close()
            self.assertIsNotNone(observer.process.returncode)
        finally:
            observer.close()


if __name__ == '__main__':
    unittest.main()
