# Managed storage

## Supported storage

Shared volumes use FUSE to access an ext4 filesystem hosted in the storage VM.
Unsupported store formats are rejected without modifying their data. cengine does
not migrate or automatically reset them. Preserve the store and its recovery
metadata; deleting markers is not recovery.

Containers and their storage/workload VMs survive API-daemon restarts, including
daemon crashes, and retain open-file DATA access while the daemon is absent.
Host reboot uses cold recovery, not live VM preservation. This does not promise
recovery from arbitrary disk faults or certify physical power-loss durability.

Local assets support development and local signed builds; canonical asset
publication and distribution acceptance are separate [release gates](release.md).

## Owner enrollment and helper compatibility

Production owner enrollment is an explicit, one-time administrator-approved action:
app onboarding/**Enable**/**Restart**, or `cengine helper setup-storage-owner` as
your normal user. `cengine helper check-storage-owner` and background startup only
check existing enrollment. The first XPC caller cannot become owner.

Production and compatibility authority use separate namespaces. The attended
`make test-compat-helper-install` provisions the compatibility owner; ordinary tests
do not require manual root-helper enrollment. Production identity never enables
test fault controls.

Ordinary runs require an authenticated protocol/capability-compatible installed
helper. Full PREPARE/fault and qualification campaigns additionally require the
exact source fingerprint and signed digest. Guest-only or engine-only changes do
not inherently require a helper reinstall; semantic authorization changes do.

## Recovery and data preservation

- **Daemon restart:** a new authenticated controller adopts the exact retained VM,
  reconciles current storage state and host intents, then restores control without
  restarting healthy containers.
- **Helper restart:** an explicit daemon restart is required to restore control;
  the replacement daemon adopts the retained storage VM.
- **Cold recovery:** positive predecessor death, exclusive backing ownership,
  authenticated mount-only proof and a fresh recovery census are required before
  admission. Established stores mount journaled ext4 without reformatting.
- **First-initialization retry:** an unused-store census and protected ROOT
  authorization permit a read-only probe followed by promotion to normal ext4.
  Partial initialization or uncertain recovery is never reset.
- **Storage-service replacement:** unlike daemon replacement, loss of the DATA
  service interrupts its shared-volume clients. Affected workload VMs need fresh
  attachments after fenced recovery; old cached work cannot receive new authority.
- **Uncertain state:** timeout, EOF, process exit and a later successful sync do not
  prove drain or recoverability. Preserve data and refuse operations where the
  required durable/native evidence is missing.

The [generation and drain contract](storage-generation-drain.md) defines DATA and
PREPARE fencing. The [lifecycle checkpoint contract](storage-production-checkpoints.md)
defines ROOT/HOST/Guest authority, live adoption, cold recovery and the bounded
committed-cold recovery exception. Neither protocol authorizes automatic disk
repair, formatting, checkpoint editing or disposal of production data.

Protected authority files contain secret signing material, including the ROOT
private key. Never copy them into ordinary logs, evidence bundles or bug reports.
Pending/uncertain authority is not disposable. Corrupt
journals require explicit privileged investigation, not automatic truncation or
reset. Successful disposable test runs may clean up their positively owned state.

## Datastore identity and permissions

Durable host identity uses filesystem UUID plus inode, not a reboot-unstable device
number. Exact live descriptor observations, backing size/ext4 UUID, store generation
and ROOT authentication remain binding-significant. Historical shim specifications
may retain a previous device number only after positive native predecessor death;
current descriptor checks remain mandatory.

Startup may tighten an owned, ACL-free datastore root from modes such as 0755 to
0700 through the descriptor held by the canonical datastore lock. It removes only
group/other read/search permissions: no recursive chmod, ownership change, ACL
removal, or repair of writable/special-bit roots. Unsupported or ambiguous storage
and unsafe child directories are checked first. The lock serializes cooperating
cengine processes, not arbitrary same-account edits; permission repair does not
verify data integrity or authorize store-format changes.

## Operational references

- [Raw runtime architecture](raw-runtime.md): VM ownership and volume placement.
- [Docker compatibility](docker-compatibility.md): supported behavior, intentional
  differences and focused compatibility contracts.
- [Development](development.md) and [Compatibility testing](compatibility-testing.md):
  local assets, signed helpers and isolated test commands.
- [Release](release.md): provenance, signing and publication requirements.

Native tests must be serialized and limited to positively owned resources. Prove
owned process exit before deleting disposable test roots. Test disposal is not a
recovery receipt; production authority and user data are not disposable fixtures.
