# RTM-103 root and object isolation

## Required contract

Managed DATA guarantees **no cross-mount authority or object access**, not globally
unique node/handle integers. A number copied from mount A can be valid on mount B
only as B's independently granted object. That does not transfer A's authority or
justify a protocol change solely to force numeric replay rejection.

## Source contract

- `Guest/internal/storagemanaged/resources_linux.go::Session.intern` maintains
  session-local node maps and counters; inode keys include the bound volume.
- `Session.getNode` resolves only that session's nodes. `Session.getHandle` checks
  its own handles plus node, type and access. `Session.grant` allocates local handles.
- `Registry.retainObject` can share opaque identity for the same bound-volume inode
  across sessions. Identity pins are not operational authority; `Session.collect`
  never migrates operational pins between views.
- `Guest/internal/storageauthority/authority.go::Authority.Admit` checks exact
  principal owner, service epoch, binding, volume and ACTIVE attachment before
  filesystem access. `Authority.Retire`/`finishRetire` durably fence and drain that
  attachment. Coincident numbers cannot revive a retired principal.

This follows ordinary [descriptor namespace isolation](https://man7.org/linux/man-pages/man2/open.2.html):
identical descriptor numbers in separate namespaces do not grant the same object.
Managed DATA adds authenticated attachment/volume admission before local lookup.

## Compatibility predicates

1. **`cross-mount-root-grant`:** establish current mounts A and B with distinguishable
   backing markers and successful own-root operations. Submit A's numeric grant
   through B's authenticated channel. A valid B alias must return attributable
   B-only content/access; otherwise require exact invalid-grant denial. Neither
   branch may expose A-exclusive content or mutate A. Recheck both legitimate
   scopes against an independent backing snapshot.
2. **`retired-root-grant-replay`:** obtain the actual receipt retiring A. A's original
   connection/principal must fail attachment authentication/admission, including
   retained object references. Fresh B may resolve coincident numbers only as its
   own grants, never as restored A attachment/key/controller privileges. Require
   fresh-owner wire IO, not just a snapshot.

Random invalid numbers, forged principals, private-boot-only failure, EOF and host
fixtures alone do not satisfy these mounted-consumer contracts. Native DATA proof,
retirement receipts, positive successor IO and owned cleanup remain distinct from
component coverage. [Docker compatibility](docker-compatibility.md) owns RTM-103's
case inventory; [Generation-fenced drain](storage-generation-drain.md) owns the
shared protocol and intentional limits.
