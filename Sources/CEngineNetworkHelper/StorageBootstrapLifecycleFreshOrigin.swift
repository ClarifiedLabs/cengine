import CEngineHelperSupport
import Foundation

/// Authenticated fresh format-completion origin for identity-verified fresh
/// initialization. Formed ONLY at the native fresh-binding seam from the actually
/// independently pinned direct shim/daemon, the exact fresh greeting (boot, disk,
/// initramfs evidence), the exact initialize grant, and ROOT's proven
/// controller candidate principal. ROOT never infers any part of this from a
/// caller DTO, the persisted binding bytes, or ext4 identity alone. It is the
/// durable prerequisite for a future identity-verified resume grant; it is not
/// itself a grant and never bypasses a route.
struct StorageLifecycleFreshOrigin: Codable, Equatable {
    let greeting: StorageLifecycleFreshProtocol.Greeting
    let shim: BootstrapProcess
    let daemon: BootstrapProcess
    let grant: Lifecycle.Grant
    let principal: BootstrapPrincipal

    /// Strong structural binding against the exact store binding and ROOT key.
    /// A persisted origin that fails any check is repair-level corruption, never
    /// something to re-derive from the binding or the caller.
    func validate(binding: StorageIdentity.StoreBinding, root: Data) throws {
        try greeting.validate(); try grant.validate()
        guard grant.operation == .initialize,
              greeting.store == grant.identity.store,
              greeting.rootPublicKey == root,
              greeting.matches(binding: binding),
              greeting.daemonUniqueID == daemon.uniqueID,
              principal.daemon == daemon,
              shim.boot == daemon.boot,
              shim.uniqueID > 0, shim.pid > 0,
              shim.uniqueID != daemon.uniqueID,
              shim.pid != daemon.pid,
              // The pinned shim is a third process, distinct from the proven
              // controller child in BOTH native identities, not an alias of it.
              shim.uniqueID != principal.child.uniqueID,
              shim.pid != principal.child.pid,
              shim.auditToken.count == 32,
              daemon.auditToken.count == 32,
              principal.child.boot == daemon.boot,
              principal.child.pid > 0, principal.child.uniqueID > 0,
              principal.child.uniqueID != daemon.uniqueID,
              principal.child.pid != daemon.pid,
              principal.child.auditToken.count == 32,
              // The grant identity must be the FULL binding-derived identity of
              // this exact store, not merely a matching store identifier.
              try grant.identity == Lifecycle.Identity(binding: binding, generation: grant.identity.generation),
              try StorageIdentity.Ed25519SPKI(publicData: principal.controllerSPKI).fingerprint.rawValue == grant.newKey
        else { throw BootstrapFailure(.repairRequired) }
    }
}
