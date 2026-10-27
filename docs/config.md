# CLI preferences

Save display preferences once for both `aswp` and `agentswapper`:

```sh
aswp config
aswp config set history.limit 50
aswp config set ui.mask true
aswp config get ui.mask
aswp config unset ui.mask
aswp config path
```

`config` is shorthand for `config list`. `list` and `get` show the effective
value, built-in default, and source (`config` or `default`). Saving a value equal
to the default still creates an explicit override. `unset` removes only that
key. Each command supports `--json`.

| Key | Values | Default | Consumer |
| --- | --- | --- | --- |
| `history.limit` | Decimal integer from 1 to 200 | `20` | Recent history from `aswp runs` |
| `ui.mask` | `true` or `false` | `false` | Initial profile-alias masking in `aswp tui` |

Explicit flags win:

```sh
aswp runs --limit 5
aswp tui --mask
aswp tui --show-aliases
```

The dashboard flags are mutually exclusive. `m` changes masking for the current
dashboard session without saving it. Saved preferences are read at startup;
profile refresh does not reload them. Masking hides displayed aliases; search
input remains visible, and it is not a security or access-control boundary.
The configured mask is applied before the first frame.

`runs RUN_ID` and `runs --limit N` do not read preferences. Dashboard flags also
bypass preference loading. Commands that consume saved defaults refuse an
invalid configuration; they do not silently fall back. `doctor` reports
preference problems separately from registry integrity. Launches, profile
management, recovery and handover do not depend on this file.

## Storage and recovery

The file is `config.json` inside the selected state directory. The same
`--state-dir` / `AGENTSWAPPER_STATE_DIR` selection used by the registry applies.
`config list`, `get` and `path` create no state, and a missing file uses defaults.
Config commands do not open or migrate SQLite, and remain usable even if the
registry needs repair. An unset on a missing state directory does nothing.

The current on-disk format is:

```json
{
  "version": 1,
  "settings": {
    "history.limit": 50,
    "ui.mask": true
  }
}
```

Only these two typed preferences are accepted. Credentials, executable paths,
engine routing and experimental execution permission are not configuration keys.
The file is limited to 4 KiB. Unknown or duplicate fields, nulls, invalid types,
out-of-range values and unsupported versions are refused. Error messages do
not echo file contents or rejected values. A newer format is distinguished from
a malformed current format within the size bound. An oversized file reports
`config_too_large` without attempting an unbounded version read. None of these
files is overwritten by `set` or `unset`.

Writers hold a separate `config.lock`, re-read the latest document under that
lock, and replace it using a private temporary file in the same directory.
Cooperating writers preserve unrelated settings; readers see a complete old or
new document. An unchanged setting is not rewritten. Lock acquisition waits at
most three seconds. Windows replacement also retries transient sharing/access
conflicts for up to three seconds, then leaves the original file intact.

The file is synchronized before replacement. On Unix, the parent directory is
synchronized afterward; if that fails, `config_durability_uncertain` explicitly
reports that the new preferences were applied. Read them back before retrying.
The parents of newly created state directories are not synchronized, so first-save
power-loss durability is unverified. Windows directory durability is best effort
and ACL privacy remains unverified.
Read snapshots remain valid when atomic replacement unlinks the old file; lock
files still require one link. Regular-file and handle checks reject symlinks, reparse points, hardlinks and
nonregular files; Unix owner/private-mode checks also apply. These checks and OS
locks do not authenticate writes against a malicious process running as you.
Use local filesystems; network-mounted storage has not been qualified.

If the file is malformed, use `aswp config path`, preserve a copy, and repair it
manually while config writers are stopped. There is no automatic reset that could erase unfamiliar settings.
The registry and vendor-owned profile files are untouched by config writes.

See [validation evidence](config-validation.md) for tests and remaining platform limits.
