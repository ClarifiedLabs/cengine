# Lifecycle managed storage service owner

`InitializeLifecycle`, `OpenLifecycle`, `ReopenLifecycle`, `ColdOpenAndTakeover`,
and `ResumeOpenAndTakeover` consume independently reconciled ROOT-signed intent.
`commonService` privately owns the shared resources.

`Config` borrows a **verified held-root descriptor** and exact ext4 device UUID/S
from the trusted private boot path. Construction does not mount or verify a VZ
disk. There is no environment, file, API, workload, or network trust override.
Open never falls back to initialization, and resume/cold-open retain their exact
signed predecessor and read-only admission requirements.

## Shared resources and credentials

`constructAuthority` creates one real `storageserver.Resources` owner and passes
its barrier, copy-recovery preflight, and PREPARE retirement proof to the lifecycle
authority opener. It then creates the fresh short-lived TLS issuer/server identity
and typed DATA server. `finishLifecycle` then installs workload CONTROL and the
lifecycle grant/result endpoint.

`Ready` is detached public S/E/C, revision, DER and pins, never activation approval.
Bootstrap trust and the boot TLS CA remain separate. No ROOT private key, CA signer,
server private key, principal, or resource owner is exposed.

- `IssueController` checks the exact current persisted S/C/key and canonical CSR.
- `AuthorizeSuccessor` pins an exact ROOT-signed lifecycle grant and issues only
  its authorized controller URI. Only real authenticated lifecycle TLS takeover
  advances the authority; issuance itself is not takeover.
- `ReconcileController` installs new workload CONTROL only after exact persisted
  takeover and joined old workload/credential workers. Existing lifecycle result
  connections need not close. DATA and retained resources are not replaced.
- `ServeAttachmentCSR` and `RequestLifecycleAttachmentCertificate` use the closed
  lifecycle credential wire, exact incarnation, current controller TLS identity,
  and registered attachment tuple. Pending successor/retirement blocks issuance.
- `ServeData` retains the typed attachment URI/SPKI verification, registry
  authentication, per-operation admission, and real resource barrier.

All credentials expire with the boot CA. Private channel routing and `Ready`
provenance remain trusted host responsibilities. Full PREPARE observations keep
all existing profile, worker, issued-certificate, and persisted-authority checks;
qualification does not gain a new authority or credential bypass.

## Retirement and shutdown

`Notifications` is a lossless bounded queue of exact authenticated DATA failures.
It does not retire attachments, release guards, or manufacture receipts. The real
Retire RPC must join admitted work and close retained managed resources. Close
rejects active workers and retained resources; socket loss is not durable drain.

## Tests

`fixture_service_test.go` retains private resource access for shared DATA, PKI,
PREPARE and durability regression tests, but uses genuine signed lifecycle
construction, CONTROL, credential issuance and reopen with the exact live-open
revision. The isolation fixture also uses lifecycle reopen for its actual
second-owner flock check. `legacy_credentials_test.go` verifies that the
credential endpoint rejects incompatible wire requests. Lifecycle replay tests
cover the signed takeover path.

```sh
cd Guest
go test -mod=readonly ./internal/storageservice ./internal/storageauthority ./internal/storagecontrol
go test -mod=readonly -tags=cengine_prepare_full_compat ./internal/storageservice ./internal/storageauthority ./internal/storagecontrol
```

Host tests are not Linux/ext4, mounted-client, physical-power-loss, VM, helper
installation, signing, or activation qualification.
