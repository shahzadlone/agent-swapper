# Windows state privacy: qualification work

Windows state and vendor profile directories are **not yet verified private**.
Handle checks for reparse points and hardlinks do not establish access-control
privacy. File and directory ACLs can be inherited from their parent, so a
successfully created directory alone is not evidence that other principals
cannot read or modify it. See Microsoft's [file security reference](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).

## Candidate audit

Source review of `windows-acl` 0.3.0 (MIT, published by Trail of Bits) found
that `ACL::all()` returns an empty entry list when the DACL pointer is null.
That list cannot be treated as evidence of a private ACL: Windows grants access
when the DACL is null or absent, whereas an empty DACL denies access. See the
[upstream implementation](https://github.com/trailofbits/windows-acl/blob/v0.3.0/src/acl.rs)
and Microsoft's [access-check reference](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck).
This observation does not determine whether other APIs in the crate are safe
for our use; it excludes using an empty enumeration as a privacy check. The
crate has not been added to AgentSwapper.

Further source review found a pointer-lifetime concern in
[`name_to_sid`](https://github.com/trailofbits/windows-acl/blob/v0.3.0/src/utils.rs):
when `system` is supplied, matching the owned `Option<Vec<u16>>` moves its vector
into an arm that returns `as_ptr()`. The vector is dropped before the following
`LookupAccountNameW` call uses that pointer. This is a source-level finding,
not an executed exploit. The descriptor and its DACL pointer are also hidden
behind private modules, so a caller cannot simply check nullness before `all()`.

An initial review of `windows-permissions` 0.2.4 at
[`8740e4e`](https://github.com/danieldulaney/windows-permissions-rs/tree/8740e4efbd88dd01046ad9c169894f3a52eb6e2c)
found that `current_process_sid()` casts a `Vec<u8>` buffer to `TOKEN_USER` and
dereferences it without an explicit alignment guarantee. That code needs a
soundness review or correction before relying on it. This is a source-level
concern, not a demonstrated exploit; the crate has not been added.

## Owned boundary decision

`agentswapper-windows-security` is a qualification candidate in the workspace;
neither the core nor CLI depends on it. Its immediate consumer is a disposable
Windows filesystem fixture. This replaces the idea of adopting an incomplete
ACL wrapper with a small owned boundary over the already-locked Microsoft
`windows-sys 0.61.2` bindings. It does not add a third-party package.

The core and CLI keep `unsafe_code = "forbid"`. This candidate uses `deny` with
one explicit exception for `ffi.rs`, and denies undocumented unsafe blocks and
unsafe operations in unsafe functions. Its parser explicitly forbids unsafe
code. This is a deliberate change to the earlier workspace-wide policy, not
unsafe code hidden inside a vendored dependency. Every native call documents
its buffer, ownership and lifetime invariants. Further independent review of
this boundary remains a promotion gate. An Opus 5.5 review at xhigh effort subsequently
completed for the `8adf85b` parser/FFI and the proposed retained-root design.
It found no ownership defect in those buffers/handles and identified device
classification and reparse qualification gaps. This is a source review, not
proof of memory safety or review of the later fixes; see the findings below.

The candidate implements:

- Process-user SID lookup without account-name resolution. Token information
  uses bounded, initialized, word-aligned storage; native pointers are checked
  against that allocation before the safe SID parser copies bytes. Thread
  impersonation is refused before identity selection, creation and reopening.
- SDDL conversion through Windows, with a protected DACL granting full control
  only to that user, LocalSystem and built-in Administrators. Those principals
  and other processes of the same user are trusted. Files use explicit ACEs;
  directories use explicit object/container-inheritable ACEs. The protected
  policy refuses inherited layouts, even if they might otherwise be secure.
  A separate direct-child file policy is described below.
- Exclusive file/directory creation through `NtCreateFile`, relative to an
  owned parent handle, with the security descriptor supplied at creation.
  Directory creation and handle acquisition are one operation. The API accepts
  one validated child name, refuses reparse traversal, and verifies the native
  creation result. Returned handles are not inheritable and do not share deletion.
  Existing objects are never adopted or repaired. Failed post-creation checks
  can leave an empty object; cleanup never deletes an uncertain pathname.
- Existing files and directories reopen relative to a validated private parent
  handle using `FILE_OPEN`, never create-or-open or overwrite. The resulting
  handle must pass the same owner/DACL, type, link and volume checks before it
  reaches the caller. File access is explicitly read-only or read/write;
  directory handles request inspection and traversal. Reopened handles also
  exclude deletion sharing and inheritance. An invalid ACL is refused without
  repair. This still requires custody of the parent and its ancestors.
- Owner/DACL snapshots via `GetSecurityInfo` on the actual file handle, with
  `LocalFree` ownership. Native descriptors must be self-relative before their
  bounded bytes are read. Owner, DACL presence, nullness, bounds, overlapping
  regions, trustee identities, ACE forms, flags and full-control masks are
  checked in safe Rust. Empty and null DACLs produce different refusals.
- Handle-based file type, reparse, link-count and volume checks. The initial
  candidate requires NTFS with persistent ACL support; other filesystems are
  refused. Path checks reject relative paths, UNC/device prefixes, alternate
  data streams, traversal, reserved devices and ambiguous trailing characters.

The [MS-DTYP descriptor layout](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d),
[self-relative descriptor contract](https://learn.microsoft.com/en-us/windows/win32/secauthz/absolute-and-self-relative-security-descriptors),
[handle security API](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo),
[SDDL conversion](https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertstringsecuritydescriptortosecuritydescriptorw),
and [volume capability API](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationbyhandlew)
define the boundary. No caller-supplied descriptor bytes are passed into native
security APIs.

Relative creation follows Microsoft's user-mode
[`NtCreateFile` contract](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)
and [`OBJECT_ATTRIBUTES` contract](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes).
Its root handle, UTF-16 buffer, native descriptor and output structures stay
alive through synchronous creation. `FILE_CREATE` never overwrites; no delete
sharing or inherited handle is requested. `create_new_at` first requires a
parent matching the private-directory policy. The absolute-path helper opens
and checks the immediate parent, then uses the same relative primitive; that
helper still requires trusted ancestors and does not qualify them itself.

The portable tests include malformed/truncated descriptors, arbitrary offsets,
null/absent/empty DACLs, broad/duplicate trustees, unfamiliar ACEs, inheritance
and overlapping components. Native fixtures cover actual creation, permissive
parent inheritance, replacement of a filename while retaining its original
handle, hardlink refusal, non-overwrite and Windows-generated descriptor forms.
Additional native fixtures replace a parent's old pathname before creating a
directory and file through its retained handle, verify that the replacement
receives nothing, and refuse traversal/stream/device names and broad parents.
They also refuse parent/child symbolic links without following them and verify
impersonation refusal on a disposable thread impersonating only its own user.
That fixture restores the thread identity on every exit; restoration failure
aborts the owned test process. It is not a separate-user access test.
Compilation is separate from native execution evidence.

An additional **ignored, CI-only** fixture creates a random local standard user
on this repository's disposable GitHub-hosted Windows runner. It requires both
the hosted-runner environment markers and `ASWP_CI_IDENTITY_FIXTURE=1` inside
the account-creation helper. Ordinary test runs skip it; invoking the ignored
test elsewhere refuses before account creation. The fixture calls `NetUserAdd`
with the local server, then `LogonUserW` and `ImpersonateLoggedOnUser` on a
dedicated thread. Its random password stays in zeroizing buffers, never argv,
environment variables, fixture files or output. It changes no existing account
or group. Cleanup owns a name only after successful creation, removes that
account explicitly after the test, and also attempts cleanup on error/unwind.

The other identity must first read and write a permissive control file. The
fixture then requires Windows `ERROR_ACCESS_DENIED` for private reads, writes,
security/delete access, removal, rename, listing and child creation; it finally
checks original file bytes and cleanup. For these ACL-only probes, owner-held
file handles are closed first, so a sharing violation cannot masquerade as an ACL denial. The
control parent grants others read/traverse, **not delete-child** access. A
permissive ancestor with deletion rights remains a separate custody problem.
The fixture also exercises that case explicitly under an additional parent
granting everyone full control. A closed private file must be removable through
parent rights. A closed private directory's result is recorded separately:
success or access denied are observations, not custody receipts. To test the
directory handle independently of ACL denial, an explicitly permissive directory
must be removable as a positive control. Equivalent attempts against a private
file and permissive directory whose creation handles remain open must fail
with access-denied or sharing-violation status. The permissive directory is also
required to fail the private-ACL policy. Actual codes are reported. This measures
a handle's protection during that interval, not a permanent guarantee for the
full path.
At `edcb5ef`, the file control was deleted, but `RemoveDirectoryW` returned
access denied for the closed directory in
[CI run 41001315576](https://github.com/shahzadlone/agent-swapper/actions/runs/41001315576).
The fixture failed before its retained-handle checks; that run does not qualify
directory custody. A subsequent DELETE-only open also returned access denied
at `fdde4bf` in [CI run 41002333737](https://github.com/shahzadlone/agent-swapper/actions/runs/41002333737),
before [file disposition](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle)
could run. The revised probe distinguishes that private-directory observation
from the successful permissive-directory control. A preexisting ACL denial is
never counted as proof that retaining a handle blocked deletion.
At `43fe407`, the revised fixture passed in the Windows test job of
[CI run 41003109095](https://github.com/shahzadlone/agent-swapper/actions/runs/41003109095).
The closed private file and closed permissive directory were deleted. Both
retained-handle attempts returned sharing violation (32). The closed private
directory returned access denied (5), independently of handle retention.
These observations qualify the fixture's measured intervals only.
This test does not cover every group policy, filesystem or vendor credential
layout. Reopening and inherited-file changes after that revision need their own
native results.

The fixture uses the documented [local account creation API](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuseradd),
[local logon API](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw)
and [thread impersonation API](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser).
Impersonation failure stops the probe, and failure to restore the thread's
identity aborts the owned test process. A killed CI job relies on destruction
of its disposable runner; it is not a supported local-machine test procedure.

The single-object APIs are not private-path APIs. Creation is anchored to the
supplied parent object, but the caller must still establish that parent's
identity and custody. They do not pin or validate the full ancestor chain,
establish custody against parent deletion rights, validate remote/mapped-drive behavior, protect
future vendor-created descendants, or qualify real vendor credential layouts. A handle
snapshot also cannot prevent later changes by trusted principals. Those gaps
must be resolved before storage integration or a privacy claim.

## Direct inherited files

SQLite creates its own WAL and shared-memory files. Those files inherit
permissions; treating them as explicitly protected files would conflate two
different policies. `open_existing_inherited_file_at` therefore requires the
parent's exact **protected directory** policy, then opens one child relative to
that handle and checks the child's actual descriptor. The existing protected
creation/open APIs keep their original policy.

The child policy requires exactly three full-control allow ACEs, all marked
inherited, for the selected user, SYSTEM and Administrators. It refuses mixed
explicit/inherited grants, inherit-only or unknown flags, a protected DACL,
other trustees, null/empty DACLs and unknown layouts. The descriptor's
`SE_DACL_AUTO_INHERITED` bookkeeping bit is optional; the inherited bit on
**every individual ACE** remains mandatory. A local Windows fixture using
atomic .NET directory creation and ordinary file creation observed inherited
ACEs without that descriptor bookkeeping bit, with both `D:P` and `D:PAI`
creation descriptors. That diagnostic does not replace the Rust native tests.
The Rust fixture at `c61fc01` confirmed the same cause in
[CI run 41005435587](https://github.com/shahzadlone/agent-swapper/actions/runs/41005435587):
control `0x8004`, owner Administrators, and exactly three inherited (`0x10`)
full-control (`0x001f01ff`) ACEs for the expected trustees. The original rule
incorrectly required `SE_DACL_AUTO_INHERITED` and refused that valid layout.
The corrected rule keeps every trustee, right and ACE flag check and permits
either bookkeeping-bit value. The failed run is diagnostic evidence only;
the correction needed its own successful native run. At `65d9960`, the actual
database/WAL/SHM checks and separate-user inherited-file probes passed in
[CI run 41007621318](https://github.com/shahzadlone/agent-swapper/actions/runs/41007621318),
along with the complete platform, package, rebuild and provenance pipeline.
The owner must be one of those same trusted principals: system-created files
can select a token's default owner. This adds no principal beyond those already
granted full control. It does not accept arbitrary vendor permission layouts.

This follows Microsoft's [ACE inheritance rules](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-inheritance-rules)
and [descriptor control flags](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-control).
Flags alone do not prove where an ACL came from. The opened parent and child
are both validated; a snapshot cannot prevent later trusted permission changes.
No permissions are repaired. Moving a broad file beneath a private parent must
not qualify it solely because of its new pathname.

Native fixtures use the same pinned bundled SQLite dependency as the core to
inspect an actual database, WAL and SHM, then verify database contents after
closing the guards and letting SQLite remove its sidecars. A separate-user
probe includes a permissive control inside the same private directory: that
control must remain readable/writable while the inherited file refuses data,
security and deletion access. This distinguishes target ACL denial from a
failure merely to traverse the directory. These fixtures require their own
successful native run before they count as qualification evidence.

This API does not yet handle inherited directories, disconnected optional
sidecar snapshots, existing-state migration or the complete retained ancestor
chain. The SQLite fixture adds only a Windows test dependency already present
in the workspace. Cross-checking its native test binary requires MSVC's C tools;
a Linux-only Rust check is not execution evidence.

## Ancestor mutation classification

`validate_ancestor_descriptor` and its handle form are a separate candidate
classification, **not a private-directory or custody API**. They currently
permit only read/list/traverse and synchronization for untrusted principals
(`0x001200a9`). Creation/deletion rights are refused pending separate
qualification. Data/EA/attribute writes and ACL/owner changes by other principals
are also refused, as are unknown ACE forms and flags. Inherit-only grants apply to
future children, so they do not qualify or disqualify the current ancestor;
every child must be independently validated. No deny ACE is used to explain
away an otherwise broad grant: this conservative candidate refuses deny ACEs.

Ancestor ownership and modification are trusted only to the selected user,
SYSTEM, Administrators and the exact Windows TrustedInstaller service SID.
The last is required for the observed system-drive root, and is confined to
ancestor classification: it is not added to private file/directory owners or
their three-principal DACL. Microsoft describes TrustedInstaller's OS role in
[Windows Resource Protection](https://learn.microsoft.com/en-us/windows/win32/wfp/about-windows-file-protection).
The local Windows temp ancestry was inspected read-only to identify actual
permission forms. Its drive root grants create-subdirectory rights, so the
narrowed ordinary-directory policy does not yet qualify that system anchor.
Native Rust fixtures classify disposable directories; they do not establish a
retained full path.

The ignored identity fixture additionally attempts a mount-point junction
mutation through [FSCTL_SET_REPARSE_POINT](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_set_reparse_point).
Its bounded byte payload follows the documented
[REPARSE_DATA_BUFFER layout](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_reparse_data_buffer).
The temporary standard user must successfully convert a permissive control
directory and read a fictional target through it. At `aa49c73`, the initially
limited mask `0x001300ed` also allowed `FSCTL_SET_REPARSE_POINT` to succeed in
[CI run 41005926230](https://github.com/shahzadlone/agent-swapper/actions/runs/41005926230).
The fixture failed and disproved that candidate permission assumption. No
production code depended on it. The narrowed rule refuses creation/deletion
rights while a revised fixture measures read-only, create-subdirectory,
delete-child, delete-self and combined rights independently. The read-only
baseline must refuse mutation; other outcomes are recorded, not counted as
successful protection. Successful mutations must redirect to the fictional
target and match the observed reparse attributes. A bad payload or missing
privilege cannot count as a successful negative test. Cleanup checks that the
target remains intact. Until these checks and component-by-component custody
pass, ancestor privacy remains unqualified.

At `65d9960`, that complete run observed successful junction mutation for
create-subdirectory and combined rights, and access denial for read-only,
delete-child and delete-self rights. Actual reparse attributes, target reads
and cleanup were verified. This supports refusing create-subdirectory rights
in the ordinary snapshot policy. It does not qualify deletion rights generally.

The next fixture reads actual handle grants with `NtQueryInformationFile` and
compares an empty directory with a parent containing a retained protected child.
The empty create-subdirectory control must redirect successfully; the nonempty
parent must return directory-not-empty (145), and the other identity must fail
to acquire deletion rights, remove or rename the protected child. This follows
the nonempty-directory rule in Microsoft's
[FSCTL operation specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/4aeefef8-92c3-4abc-af7a-a610caf8a165).
Handle grants, original child bytes and reparse attributes are checked. A
successful empty control is required before any nonempty result is credited.
At `5c64085`, this fixture and the complete three-platform pipeline passed in
[CI run 41107861061](https://github.com/shahzadlone/agent-swapper/actions/runs/41107861061).
The reported granted masks exactly matched each requested matrix mask, including
`0x001200ad` for create-subdirectory access, without write-data or
write-attributes rights. The matched nonempty parent refused junction creation
with error 145, and the protected child refused deletion access, removal and
rename. These measurements cover that disposable NTFS fixture and mount-point
operation; they do not establish a full-path guard or every reparse operation.
The public ancestor snapshot policy continues to refuse create-subdirectory rights.
No actual system-drive root is mutated.

The follow-up fixture also exercises `FSCTL_SET_REPARSE_POINT_EX` with its own
fresh empty control and the same nonempty parent. It constructs the documented
[extended buffer header](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_reparse_data_buffer_ex)
with no existing tag and verifies the control's actual redirection before
requiring error 145 from the nonempty case. This needs its own native result;
passing the older operation does not qualify the extended one.
At `8adf85b`, both operations and the complete three-platform pipeline passed in
[CI run 41134874184](https://github.com/shahzadlone/agent-swapper/actions/runs/41134874184).

## Retained root candidate

`open_or_create_private_root` now constructs a separate `PrivateRoot` candidate.
It opens an actual fixed NTFS volume root, then opens each directory relative
to the preceding retained handle. Missing directories use exclusive creation
with the protected policy at creation time; a competing creator is handled by
one reopen and validation, never by adoption without inspection or ACL repair.
All handles exclude write/delete sharing and inheritance. Directory handles
retain TRAVERSE/EXECUTE access so that their sharing restrictions participate
in the filesystem's share accounting. The final directory must
match the exact protected three-principal policy. Existing inherited roots are
refused, not automatically migrated.

Only this constructor uses an internal ancestor policy allowing
create-subdirectory (`0x4`) in addition to the public read-only mask. Every
retained child is independently checked, every ancestor refuses untrusted
DELETE and DELETE_CHILD, and the complete chain is checked again from leaf to
volume root before returning. A nonempty chain alone is not credited as
protection against every reparse tag: retained public-ancestor handles additionally
exclude write access, including ADD_SUBDIRECTORY/APPEND_DATA. Exact private
directories use their three-principal DACL and retain deletion exclusion while
permitting owner writes, as explained in the consumer qualification below. The implementation does
not treat a standalone AD4 descriptor snapshot as safe. Reparse checks occur again after child acquisition;
no sensitive data is written during construction. Failures can leave empty
protected directories, which are not removed through uncertain pathnames.

[`GetDriveTypeW`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypew)
must classify the anchor as fixed. A separate normalized, volume-relative
[`GetFinalPathNameByHandleW`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew)
result must identify only the volume root, so a SUBST alias to a subdirectory
cannot silently omit its ancestors. The leaf path comes from its actual handle
in normalized, validated verbatim DOS form, with the original drive letter.
The verbatim prefix must not be stripped by consumers. UNC, device and removable roots are unsupported;
path length and component count are bounded. Drive namespace changes and
changes by the user, SYSTEM, Administrators and TrustedInstaller are trusted.
Previously acquired mutation rights are not revoked by a descriptor snapshot.

The guard must outlive every pathname-based user, especially SQLite connections.
Native fixtures cover protected creation/reopen, ancestor rename attempts,
concurrent constructors, long paths, reparse/broad-ACL refusal and impersonation.
The first implementation passed the native Windows test job at `32bb0ad` in
[CI run 41135840809](https://github.com/shahzadlone/agent-swapper/actions/runs/41135840809).
That result predates write-sharing exclusion and device-information checks.
Their later native results are recorded below. Independent review of the
follow-up code, migration and storage integration remain gates. Neither
the core nor CLI links this candidate, and `doctor` still reports Windows ACL
privacy as unverified.

The combined CI-only fixture uses a newly owned directory under the runner's
profile, two AD4 ancestors and an actual live SQLite database/WAL/SHM. It keeps
the connection ahead of the guard in field-drop order. A permissive fictional
file inside the same private leaf proves reachability; no privileged handles
enter the other user's thread. Empty reparse controls must succeed, while
AD4/MAXIMUM_ALLOWED opens against retained ancestors must fail with sharing
violation and metadata-only reparse attempts must be denied. The fixture also
checks private reads/writes/deletes, child injection, renames and original data.

A separate hosted-runner-only fixture creates a transient, previously unused
DOS drive alias to its own directory via
[`DefineDosDeviceW`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-definedosdevicew).
The mutating helper enforces the CI markers, refuses thread impersonation and
LocalSystem's global namespace, and records ownership only after successful
creation. Removal matches the exact raw target and runs on error/unwind too.
A readable alias is the positive control; the private-root constructor must
refuse omitted ancestry before creating a child. Target preservation and alias
removal are checked. Native results are recorded below.

At `e8eb961`, the ordinary Windows tests and both ACL qualification steps passed
in [CI run 41137050356](https://github.com/shahzadlone/agent-swapper/actions/runs/41137050356).
This includes the combined separate-user SQLite/chain control, metadata-only
sharing control, preexisting/later writer refusal and SUBST-equivalent alias
refusal. It does not include the subsequent loopback SMB probe or establish
production storage privacy.

## Independent review follow-up

The completed Opus review identified that NTFS naming and persistent-ACL flags
alone do not establish a local device: a Windows network filesystem can report
those properties too. `validate_object` now queries the actual handle through
`NtQueryVolumeInformationFile(FileFsDeviceInformation)` and requires a disk
without remote/removable-media characteristics, before trusting an ACL snapshot.
The fixed-size initialized output and returned byte count are checked. See
[the device information contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_fs_device_information)
and [volume query contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwqueryvolumeinformationfile).
The negative native control below tests an actual remote handle.

The follow-up ignored fixture creates a unique temporary SMB share containing
only a fresh fictional file, with share access restricted to the fixture user's
SID. The mutating helper checks the hosted-runner opt-in itself; it does not
change service, firewall, account or existing-share policy. Local validation
must succeed, a loopback SMB read of the same bytes must succeed, and validation
of that remote handle must specifically return `UnsupportedObject`. Share
removal is explicit with unwind cleanup, followed by absence and original-file
checks. Its API contracts are
[`NetShareAdd`](https://learn.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netshareadd)
and [`NetShareDel`](https://learn.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netsharedel).

The review also raised directory-bit reparse tags as an unmeasured attack
hypothesis. Microsoft describes tags whose directories may contain children in
[reparse restrictions](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points).
Mount-point error 145 does not qualify those other operations. The follow-up
therefore excludes write sharing while retaining the existing ACL/type checks;
it must measure preexisting and later writers, MAXIMUM_ALLOWED, metadata-only
operations and compatibility on the actual volume root. A metadata-only handle
is an explicit control, not a substitute for the guard's TRAVERSE/EXECUTE access.

A subsequent local Windows experiment confirmed the distinction. An AD4-only
handle installed and removed a non-Microsoft directory-bit tag (`0x10000042`,
with a fresh GUID) on both empty and nonempty disposable directories. A
READ_ATTRIBUTES-only handle under the stronger retained guard refused the same
operation with access denied (5). Original canaries and cleanup passed. This
used the current user's handles, not a separate identity, and tested the basic
operation only. It disproves using nonemptiness as a general reparse barrier;
the earlier `32bb0ad` guard must not be promoted on its original evidence.

The follow-up CI regression repeats both basic and extended operations under
the temporary standard user. A nonempty AD4 control must accept the directory
tag, show its actual reparse attribute, and permit exact tag/GUID removal.
Two metadata-only ancestor handles under the full guard must refuse the same
valid inputs. Control-tag cleanup runs on unwind as well. This uses only
disposable fixture objects; the tag is not used in product storage.

At `838d8ed`, [CI run 41138470554](https://github.com/shahzadlone/agent-swapper/actions/runs/41138470554)
passed both native ACL steps, all three platform jobs, candidate packaging,
separate-runner binary comparisons and preview provenance verification. This
includes the actual loopback SMB read/refusal/cleanup and separate-user basic
and extended directory-bit reparse controls. The earlier SMB revision
`e694f70` passed those Windows probes but failed an unrelated POSIX terminal
fixture; it is not recorded as a successful complete pipeline.

The low-level absolute creation helper remains explicitly dependent on trusted
ancestors; the full constructor does not use it. Same-user processes, OS
namespace administration and privileged access that bypasses DACLs remain
outside the ordinary-other-user privacy model. Integrity-label sandboxing is
not claimed. SQLite temporary storage must be constrained during integration;
the combined fixture uses `temp_store=MEMORY`. A custom handle-relative SQLite
VFS is an alternative if pathname custody or compatibility cannot be qualified,
not an implemented component. A completed review of older code does not approve
these follow-up implementations automatically.

## Inherited descendants

Vendor-created subdirectories need a separate descriptor policy. The candidate
now recognizes only the same exact user/SYSTEM/Administrators full-control
entries, each effective and inherited with both object and container propagation
(`0x13`). Files retain their distinct inherited-only `0x10` rule. Explicit,
inherit-only, nonpropagating, broad or unsupported entries are refused. The
descriptor's auto-inherited bookkeeping bit remains optional; the per-entry
inheritance bit is mandatory. This follows the documented
[ACE inheritance rules](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-inheritance-rules),
and does not infer parentage merely from a flag.

The relative inherited-directory opener validates its actual private parent,
then opens the child without deletion sharing and checks its type, device
and exact descriptor. Parents may be protected or strictly inherited; callers
must retain every handle to the guarded root. The inherited-file opener accepts
that same parent policy. These operations never create missing children or
repair permissions. Existing root admission and protected-object APIs remain
strict; legacy migration is not implied.

The separate `open_existing_private_root` operation acquires the complete
ancestor chain without creating missing components. It admits either a protected
leaf or an already-private, strictly inherited leaf. This supports read-only
state access and safe admission of existing layouts; broader legacy ACLs remain
errors, with no automatic repair or credential copying. The creation constructor
still requires a protected leaf. Native tests compare descriptors and canary
bytes before and after admission and require missing paths to remain absent.
The separate-user fixture retains an inherited root through this full constructor
while probing nested privacy. These new root-admission checks need native results.

Portable tests cover all flags, changed permissions/trustees, owner choices,
truncation and randomized offsets. Native fixtures cover ordinary multilevel
creation, unchanged descriptors, relative reopen, retained rename refusal,
missing/reparse/traversal refusal and a broad-parent negative control. The
separate-user chain fixture adds a readable nested public control alongside
private inherited data and checks read/write/delete, injection and directory
rename refusal. These additions still require their own native results and
review. They qualify filesystem behavior, not real vendor credential layouts.

## Required before a privacy claim

Required files and replaceable read snapshots have different link semantics.
The candidate's `open_existing_private_file_at` accepts protected or strictly
inherited files only after validating their actual private parent, and keeps
the exactly-one-link/no-delete-sharing rule. A separate
`validate_private_file_snapshot` checks an already-open file with zero or one
links, for configuration replacement or SQLite retirement. It still checks
the actual device, reparse status and exact private ACL. It never establishes
that a name still references the snapshot and must not validate required locks.
Native fixtures retire both protected and inherited files, preserve original
bytes, reject multiple links and reject broad ACLs even after unlinking.
The actual core fixture retains an old config read handle across replacement
and requires both a private old snapshot and the new saved preferences. These
snapshot additions need native results; the core is not yet wired to them.

The first snapshot run at `4aee481` passed the protected-file case but refused
the detached inherited-file descriptor in
[CI run 41141525367](https://github.com/shahzadlone/agent-swapper/actions/runs/41141525367).
A disposable local Windows reproduction using the same protected creation SDDL
showed NTFS clearing the inherited ACE flags after final unlink while retaining
the same three full-control grants and original bytes. A directory set up through
automatic ACL propagation did not show that transformation on the same host.
The zero-link snapshot path now accepts either uniformly explicit or uniformly
inherited file ACEs, with the same exact trustees, owner set and rights. The
handle's link count is read after the ACL snapshot; named files and required
opens do not use this detached-only policy. Broad/mixed/unknown grants remain
refusals. Portable mutation tests cover the additional layout; native hosted
qualification remains required.

A consumer-compatibility fixture now wraps the actual core `Store`,
`ConfigStore` and `ProfileLease` in an externally retained candidate root. It
creates only fictional profiles and data, verifies every registry/sidecar,
configuration, lock and profile-file descriptor, replaces settings twice,
and checks registry replay plus a concurrent reopen. The separate-user probe
must reach a public control in that exact profile directory while private
reads/writes/deletes, child injection and directory renames fail. The owner
then checks original application state. These additions await native results.
`agentswapper-core` is a Windows-only **test dependency of the candidate**;
the production core still does not depend on or own the guard. No new registry
package is introduced. This fixture addresses consumer compatibility but
does not by itself establish correct guard lifetimes throughout production.

The first actual-core run at `74c1b36` failed at the initial settings save with
sharing violation (32) in
[CI run 41141137639](https://github.com/shahzadlone/agent-swapper/actions/runs/41141137639).
The all-directory write-sharing exclusion is incompatible with normal settings
replacement. The constructor now classifies each retained directory: an exact
private DACL permits write sharing; a public ancestor requires a write-excluding
reopen and fresh validation **before any child lookup or creation**. The original
handle keeps deletion excluded during that reopen. Final checks use each
handle's original policy class, so a private handle cannot silently fall back to
the broader ancestor policy. The volume anchor still excludes writes/deletion.

The public AD4 preexisting/later-writer and reparse probes remain mandatory.
A private-directory positive control must allow an owner write handle, concurrent
root reopening and child rename while refusing rename of the retained directory.
Actual settings replacement and registry use must also pass. This refined
sharing policy still needs native qualification and independent review; the
older successful synthetic SQLite probe did not qualify this consumer behavior.
The same run also caught a missing version on the local core test dependency;
that dependency now has an exact workspace-version requirement and still adds
no third-party package.

The initial candidate's seven native fixtures and portable parser tests passed
at `54c7b19` in [CI run 40999147184](https://github.com/shahzadlone/agent-swapper/actions/runs/40999147184),
including the complete candidate/rebuild/provenance pipeline. This is evidence
for the initial snapshot/creation implementation only. At `444cd71`, the expanded
eleven native fixtures, twelve portable parser tests and full pipeline passed
in [CI run 40999776258](https://github.com/shahzadlone/agent-swapper/actions/runs/40999776258).
That run covers parent-handle creation, replacement, reparse and impersonation
refusal. At `515e519`, the native separate-identity fixture passed in
[CI run 41000440257](https://github.com/shahzadlone/agent-swapper/actions/runs/41000440257):
the temporary standard user read/wrote the permissive control and received
access-denied errors for the protected operations; original bytes and account
removal were checked. That result predates the parent-delete-child experiment
and does not establish production privacy. Its complete pipeline, including
candidate builds, separate-runner rebuild comparisons and preview provenance,
also passed. Later code changes need their own results.

The implementation must establish an appropriate owner and restrictive DACL
for the actual opened objects, distinguish null from empty DACLs, handle
inheritance and unknown ACE forms conservatively, and refuse unsupported
filesystems or ambiguous observations. New private directories need protection
at creation, before credentials or sensitive data can be written. Validation
must cover directory traversal and replacement races as well as files; merely
checking a pathname and reopening it is insufficient. Administrative and
system access, existing state migration, and vendor-created descendants need
an explicit policy and measured tests with separate Windows identities. Until
those gates pass, `doctor` continues to report ACL privacy as unverified.
