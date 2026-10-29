#!/usr/bin/env python3
"""Exercise the real Windows dashboard through an isolated ConPTY and fake agents.

Uses the documented CreatePseudoConsole / STARTUPINFOEX sequence. Handles belong
only to this fixture; teardown never signals a PID from the run journal.
"""
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid


class Coord(c.Structure):
    _fields_ = [("X", c.c_short), ("Y", c.c_short)]


class StartupInfo(c.Structure):
    _fields_ = [("cb", w.DWORD), ("lpReserved", w.LPWSTR), ("lpDesktop", w.LPWSTR),
                ("lpTitle", w.LPWSTR), ("dwX", w.DWORD), ("dwY", w.DWORD),
                ("dwXSize", w.DWORD), ("dwYSize", w.DWORD), ("dwXCountChars", w.DWORD),
                ("dwYCountChars", w.DWORD), ("dwFillAttribute", w.DWORD),
                ("dwFlags", w.DWORD), ("wShowWindow", w.WORD), ("cbReserved2", w.WORD),
                ("lpReserved2", c.POINTER(w.BYTE)), ("hStdInput", w.HANDLE),
                ("hStdOutput", w.HANDLE), ("hStdError", w.HANDLE)]


class StartupInfoEx(c.Structure):
    _fields_ = [("StartupInfo", StartupInfo), ("lpAttributeList", c.c_void_p)]


class ProcessInfo(c.Structure):
    _fields_ = [("hProcess", w.HANDLE), ("hThread", w.HANDLE),
                ("dwProcessId", w.DWORD), ("dwThreadId", w.DWORD)]


class Api:
    def __init__(self):
        if os.name != "nt":
            raise RuntimeError("ConPTY fixture requires Windows")
        self.dll = c.WinDLL("kernel32", use_last_error=True)
        declarations = {
            "CreatePipe": (w.BOOL, [c.POINTER(w.HANDLE), c.POINTER(w.HANDLE), c.c_void_p, w.DWORD]),
            "CloseHandle": (w.BOOL, [w.HANDLE]),
            "CreatePseudoConsole": (c.c_int32, [Coord, w.HANDLE, w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]),
            "ResizePseudoConsole": (c.c_int32, [w.HANDLE, Coord]),
            "ClosePseudoConsole": (None, [w.HANDLE]),
            "InitializeProcThreadAttributeList": (w.BOOL, [c.c_void_p, w.DWORD, w.DWORD, c.POINTER(c.c_size_t)]),
            "UpdateProcThreadAttribute": (w.BOOL, [c.c_void_p, w.DWORD, c.c_size_t, c.c_void_p, c.c_size_t, c.c_void_p, c.c_void_p]),
            "DeleteProcThreadAttributeList": (None, [c.c_void_p]),
            "CreateProcessW": (w.BOOL, [w.LPCWSTR, w.LPWSTR, c.c_void_p, c.c_void_p, w.BOOL, w.DWORD,
                                        c.c_void_p, w.LPCWSTR, c.POINTER(StartupInfo), c.POINTER(ProcessInfo)]),
            "ReadFile": (w.BOOL, [w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p]),
            "WriteFile": (w.BOOL, [w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p]),
            "WaitForSingleObject": (w.DWORD, [w.HANDLE, w.DWORD]),
            "GetExitCodeProcess": (w.BOOL, [w.HANDLE, c.POINTER(w.DWORD)]),
            "TerminateProcess": (w.BOOL, [w.HANDLE, w.UINT]),
        }
        for name, (result, args) in declarations.items():
            function = getattr(self.dll, name)
            function.restype = result
            function.argtypes = args
            setattr(self, name, function)

    @staticmethod
    def require(result):
        if not result:
            raise c.WinError(c.get_last_error())


class Session:
    def __init__(self, command, env, cwd):
        self.api = Api()
        self.input_read, self.input_write = w.HANDLE(), w.HANDLE()
        self.output_read, self.output_write = w.HANDLE(), w.HANDLE()
        self.console = w.HANDLE()
        self.process = None
        self.reader = self.writer = None
        self.output = bytearray()
        self.error = None
        self.condition = threading.Condition()
        self.outgoing = queue.Queue(maxsize=128)
        attributes = None
        attributes_initialized = False
        try:
            self.api.require(self.api.CreatePipe(c.byref(self.input_read), c.byref(self.input_write), None, 0))
            self.api.require(self.api.CreatePipe(c.byref(self.output_read), c.byref(self.output_write), None, 0))
            result = self.api.CreatePseudoConsole(Coord(100, 32), self.input_read, self.output_write, 0, c.byref(self.console))
            if result < 0:
                raise RuntimeError(f"CreatePseudoConsole failed: HRESULT 0x{result & 0xffffffff:08x}")
            # Separate channel workers keep output draining during input writes
            # and ClosePseudoConsole's final-frame flush.
            self.reader = threading.Thread(target=self._read, daemon=True)
            self.writer = threading.Thread(target=self._write, daemon=True)
            self.reader.start()
            self.writer.start()
            size = c.c_size_t()
            self.api.InitializeProcThreadAttributeList(None, 1, 0, c.byref(size))
            if not 0 < size.value <= 65536:
                raise RuntimeError("invalid startup attribute size")
            attributes = c.create_string_buffer(size.value)
            self.api.require(self.api.InitializeProcThreadAttributeList(attributes, 1, 0, c.byref(size)))
            attributes_initialized = True
            # The documented API takes the HPCON value itself as lpValue.
            self.api.require(self.api.UpdateProcThreadAttribute(attributes, 0, 0x00020016,
                                                                self.console, c.sizeof(w.HANDLE), None, None))
            startup = StartupInfoEx()
            startup.StartupInfo.cb = c.sizeof(StartupInfoEx)
            startup.lpAttributeList = c.cast(attributes, c.c_void_p)
            process = ProcessInfo()
            line = c.create_unicode_buffer(subprocess.list2cmdline(command))
            environment = c.create_unicode_buffer("\0".join(f"{key}={value}" for key, value in
                                                            sorted(env.items(), key=lambda pair: pair[0].upper())) + "\0\0")
            self.api.require(self.api.CreateProcessW(command[0], line, None, None, False,
                                                     0x00080000 | 0x00000400, environment, str(cwd),
                                                     c.cast(c.byref(startup), c.POINTER(StartupInfo)), c.byref(process)))
            self.process = process.hProcess
            self.api.CloseHandle(process.hThread)
            self._close_handle(self.input_read)
            self._close_handle(self.output_write)
        except BaseException:
            self.close()
            raise
        finally:
            if attributes_initialized:
                self.api.DeleteProcThreadAttributeList(attributes)

    def _close_handle(self, handle):
        if handle.value:
            self.api.CloseHandle(handle)
            handle.value = None

    def _fail(self, error):
        with self.condition:
            if self.error is None:
                self.error = error
            self.condition.notify_all()

    def _read(self):
        buffer = c.create_string_buffer(65536)
        scan = 0
        while True:
            count = w.DWORD()
            if not self.api.ReadFile(self.output_read, buffer, len(buffer), c.byref(count), None):
                error = c.get_last_error()
                if error not in (6, 109, 232):
                    self._fail(RuntimeError(f"ConPTY read failed: {error}"))
                return
            if not count.value:
                return
            with self.condition:
                if len(self.output) + count.value <= 4 * 1024 * 1024:
                    self.output.extend(buffer.raw[:count.value])
                    while True:
                        found = self.output.find(b"\x1b[6n", scan)
                        if found < 0:
                            scan = max(scan, len(self.output) - 3)
                            break
                        scan = found + 4
                        try:
                            self.outgoing.put_nowait((b"\x1b[1;1R", None))
                        except queue.Full:
                            self.error = RuntimeError("ConPTY response queue exceeded budget")
                elif self.error is None:
                    # Continue draining after a budget failure so teardown can
                    # still complete without filling the synchronous pipe.
                    self.error = RuntimeError("ConPTY output exceeded fixture budget")
                self.condition.notify_all()

    def _write(self):
        while True:
            item = self.outgoing.get()
            if item is None:
                return
            data, acknowledgement = item
            try:
                count = w.DWORD()
                self.api.require(self.api.WriteFile(self.input_write, data, len(data), c.byref(count), None))
                if count.value != len(data):
                    raise RuntimeError("incomplete ConPTY input write")
            except BaseException as error:
                self._fail(error)
            finally:
                if acknowledgement is not None:
                    acknowledgement.set()

    def send(self, data):
        acknowledgement = threading.Event()
        self.outgoing.put((data, acknowledgement), timeout=2)
        if not acknowledgement.wait(3):
            raise TimeoutError("ConPTY input writer did not acknowledge input")
        if self.error is not None:
            raise self.error

    def alive(self):
        if self.process is None:
            return False
        status = self.api.WaitForSingleObject(self.process, 0)
        if status not in (0, 258):
            raise RuntimeError(f"process wait failed: {status}")
        return status == 258

    def wait_output(self, marker, timeout=15):
        deadline = time.monotonic() + timeout
        with self.condition:
            while marker not in self.output:
                if self.error is not None:
                    raise self.error
                if not self.alive() or time.monotonic() >= deadline:
                    raise AssertionError(f"ConPTY did not render {marker!r}; tail={bytes(self.output[-1500:])!r}")
                self.condition.wait(0.05)

    def resize(self, width, height):
        if self.api.ResizePseudoConsole(self.console, Coord(width, height)) < 0:
            raise RuntimeError("ConPTY resize failed")

    def close(self):
        if self.process is not None:
            if self.alive():
                self.api.TerminateProcess(self.process, 125)
                self.api.WaitForSingleObject(self.process, 3000)
            self.api.CloseHandle(self.process)
            self.process = None
        self._close_handle(self.input_read)
        self._close_handle(self.output_write)
        if self.console.value:
            if self.reader is None or not self.reader.is_alive():
                self._close_handle(self.output_read)
            self.api.ClosePseudoConsole(self.console)
            self.console.value = None
        if self.writer is not None:
            self.outgoing.put(None, timeout=2)
            self.writer.join(timeout=2)
        if self.reader is not None:
            self.reader.join(timeout=2)
        self._close_handle(self.input_write)
        self._close_handle(self.output_read)


def check(binary, fixture):
    with tempfile.TemporaryDirectory(prefix="aswp-conpty-") as directory:
        root = Path(directory).resolve()
        (root / "bin").mkdir()
        (root / "workspace").mkdir()
        for name in ["claude", "codex", "kimi", "gents"]:
            shutil.copyfile(fixture, root / "bin" / f"{name}.exe")
        env = {key: value for key, value in os.environ.items()
               if key.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP"}}
        env.update({key: str(root) for key in ["HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"]})
        env.update({"PATH": str(root / "bin"), "TERM": "xterm-256color", "ASWP_CONPTY_FIXTURE": "1"})
        command = [str(binary), "--state-dir", str(root / "state")]

        def cli(*args):
            return subprocess.run(command + list(args), cwd=root / "workspace", env=env,
                                  check=True, capture_output=True, timeout=15)

        for name, alias in [("claude", "alpha-canary"), ("codex", "beta-canary"), ("kimi", "gamma-canary")]:
            cli("profile", "add", name, "--alias", alias)
        cli("profile", "add", "gents", "--alias", "relay-canary", "--address", "127.0.0.1:9191", "--agent", "agent-canary")
        cli("config", "set", "ui.mask", "true")
        profiles = json.loads(cli("list", "--json").stdout)["data"]
        homes = {entry["profile"]["harness"]: root / "state" / "profiles" / entry["profile"]["id"] for entry in profiles}
        (homes["gents"] / "runtime.json").write_text(json.dumps({"home": str(homes["gents"]), "graphql": "http://127.0.0.1:9191/api/v0/graphql"}), encoding="utf-8")
        session = Session([str(fixture), "__fixture_host", str(binary), str(root)], env, root / "workspace")

        def until(check, description, timeout=20):
            deadline = time.monotonic() + timeout
            while True:
                result = check()
                if result is not None:
                    return result
                if session.error is not None:
                    raise session.error
                if not session.alive() or time.monotonic() >= deadline:
                    raise AssertionError(f"{description}; output tail={bytes(session.output[-1500:])!r}")
                time.sleep(0.02)

        def read_json(path):
            try:
                return json.loads(path.read_bytes())
            except (OSError, ValueError):
                return None

        def raw_dashboard():
            request = uuid.uuid4().hex
            temporary = root / f"request-{request}"
            temporary.write_text(request, encoding="ascii")
            os.replace(temporary, root / "mode-request")

            def observed():
                state = read_json(root / "mode-response.json")
                if state and state["request"] == request and state["inputMode"] & 6 == 0:
                    return state
                return None
            return until(observed, "dashboard did not return to raw input")

        def history():
            return json.loads(cli("runs", "--json").stdout)["data"]

        def launched(number, keys):
            raw_dashboard()
            session.send(keys + b" \r")
            record = until(lambda: read_json(root / f"launch-{number}.json"), f"fixture agent {number} did not start")
            assert record["inputMode"] & 6 == 6, "agent inherited raw dashboard input"
            assert Path(record["home"]).resolve() == homes[record["agent"]].resolve()
            return record

        def finished(number, code, interrupt=False):
            if interrupt:
                session.send(b"\x03")
            else:
                (root / f"stop-{number}").touch()

            def recorded():
                runs = history()
                if len(runs) == number and runs[0]["exitCode"] is not None:
                    assert runs[0]["exitCode"] & 0xffffffff == code & 0xffffffff
                    return runs[0]
                return None
            result = until(recorded, "agent exit was not journaled")
            raw_dashboard()
            return result

        try:
            session.wait_output(b"aswp")
            raw_dashboard()
            assert b"alpha-canary" not in session.output
            session.send(b"\r")
            session.wait_output(b"Unmask")
            assert b"alpha-canary" not in session.output
            session.send(b" \r")
            time.sleep(0.2)
            assert not (root / "sequence").exists(), "masked review started an agent"
            session.send(b"\x07\r\x10 \r")
            first = until(lambda: read_json(root / "launch-1.json"), "first reviewed launch did not start")
            assert first["agent"] == "claude" and first["args"] == []
            finished(1, 42)
            login = launched(2, b"l")
            assert login["agent"] == "claude" and login["args"] == ["auth", "login"]
            finished(2, 0)
            codex = launched(3, b"j\r")
            assert codex["agent"] == "codex" and codex["args"] == []
            finished(3, 0xc000013a, interrupt=True)
            session.resize(44, 17)
            kimi = launched(4, b"j\r")
            assert kimi["agent"] == "kimi" and kimi["args"] == []
            finished(4, 0)
            gents = launched(5, b"j\r")
            assert gents["agent"] == "gents" and gents["args"][0] == "chat"
            source = finished(5, 0)
            resumed = launched(6, b"c")
            assert resumed["args"] == gents["args"]
            latest = finished(6, 0)
            assert latest["gentsSession"]["id"] == source["gentsSession"]["id"]
            assert latest["gentsSession"]["resumedFrom"] == source["id"]
            assert latest["custody"] == "external_runtime_unknown"
            # Rename and unregister stay inside the dashboard and keep using
            # the same profile identity. Editing remains private throughout.
            session.send(b"\x10n\x15quiet-relay\r")

            def renamed():
                rows = json.loads(cli("list", "--json").stdout)["data"]
                return next((row["profile"] for row in rows if row["profile"]["alias"] == "quiet-relay"), None)
            renamed_profile = until(renamed, "dashboard rename did not persist")
            assert renamed_profile["id"] == homes["gents"].name
            raw_dashboard()
            session.send(b"d\r ")
            session.send(b"\x10\r")
            time.sleep(0.2)
            assert renamed() is not None, "privacy toggle did not reset unregister acceptance"
            session.send(b"\x10 \r")
            until(lambda: True if renamed() is None else None, "dashboard unregister did not persist")
            assert (homes["gents"] / "runtime.json").exists(), "unregister removed engine-owned files"
            raw_dashboard()
            session.send(b"\x10")
            session.resize(34, 10)
            session.send(b"\r \r")
            time.sleep(0.2)
            assert (root / "sequence").read_text() == "6", "tiny-terminal review started an agent"
            session.resize(100, 32)
            session.send(b"\x07q")
            result = until(lambda: read_json(root / "console-result.json"), "dashboard did not restore its console")
            assert result["exitCode"] == 0 and result["inputBefore"] == result["inputAfter"]
            assert result["outputBefore"] == result["outputAfter"]
            for number in range(1, 7):
                record = read_json(root / f"launch-{number}.json")
                assert record["inputMode"] == result["inputBefore"]
                assert record["outputMode"] == result["outputBefore"]
            until(lambda: True if not session.alive() else None, "console host did not exit")
            code = w.DWORD()
            session.api.require(session.api.GetExitCodeProcess(session.process, c.byref(code)))
            assert code.value == 0
            assert len(history()) == 6
            cli("registry", "verify")
        finally:
            session.close()
    print("Windows ConPTY: native/login/gents launch, manual brand change, resume, Ctrl-C, resize, privacy and exact console restoration passed")


def main():
    if os.name != "nt" or len(sys.argv) != 3:
        raise SystemExit("Usage on Windows: check_windows_dashboard_conpty.py PATH_TO_ASWP PATH_TO_WINDOWS_DASHBOARD_PROBE")
    check(Path(sys.argv[1]).resolve(strict=True), Path(sys.argv[2]).resolve(strict=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        message = str(error).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::error title=Windows dashboard ConPTY::{message}", flush=True)
        raise
