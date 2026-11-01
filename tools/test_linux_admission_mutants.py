"""Ordinary-user mutation and diagnostic guards; no service installation."""
from pathlib import Path
import unittest

from build_linux_admission_mutants import BARRIER, TRANSITION, KINDS, mutate
from check_linux_socket_activation import generation_result


class AdmissionMutationTests(unittest.TestCase):
    def test_only_the_reviewed_transition_moves_or_disappears(self):
        path = Path(__file__).resolve().parents[1] / 'crates/agentswapper-linux-manager/src/service.rs'
        original = path.read_text()
        missing = mutate(original, 'missing-transition')
        self.assertNotIn(TRANSITION, missing)
        early = mutate(original, 'premature-transition')
        self.assertIn(TRANSITION + BARRIER, early)
        self.assertEqual(early.replace(TRANSITION, ''), missing)
        for kind in KINDS:
            for invalid in (original + TRANSITION, original.replace(BARRIER, ''), ''):
                with self.subTest(kind=kind), self.assertRaisesRegex(RuntimeError, 'exactly one'):
                    mutate(invalid, kind)

    def test_mutant_must_fail_at_its_exact_expected_boundary(self):
        diagnostic = 'selector switch during admission was accepted'
        error = ('generation probe refused: ' + diagnostic + '\n').encode()
        success = b'generation: before-final-check passed\n'
        generation_result('before-final-check', 0, success, b'', None)
        generation_result('before-final-check', 125, b'', error, diagnostic)
        for code, stdout, stderr in ((0, success, b''), (1, b'', error),
                                     (125, b'', b'wrong boundary\n'), (125, b'extra', error)):
            with self.subTest(code=code, stderr=stderr), self.assertRaises(RuntimeError):
                generation_result('before-final-check', code, stdout, stderr, diagnostic)
        with self.assertRaises(RuntimeError):
            generation_result('before-final-check', 125, b'', error, None)


if __name__ == '__main__':
    unittest.main()
