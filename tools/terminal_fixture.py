"""Shared terminal-configuration comparison for POSIX integration fixtures."""
import sys
import termios


def same_terminal_configuration(before, after):
    before = list(before)
    after = list(after)
    if sys.platform == "darwin":
        # XNU can set PENDIN while switching back to canonical input. It is a
        # transient kernel input state, not a terminal configuration setting.
        # Every other bit and field, including VMIN and VTIME, remains exact.
        pendin = getattr(termios, "PENDIN", 0x20000000)
        before[3] &= ~pendin
        after[3] &= ~pendin
    return before == after
