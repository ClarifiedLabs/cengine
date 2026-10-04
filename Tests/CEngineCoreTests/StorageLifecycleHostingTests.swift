#if os(macOS)
import CEngineCore
@testable import CEngineRuntime
import Darwin
import Foundation
import Testing

@Suite("Lifecycle-v2 storage hosting (no VM)")
@MainActor
struct StorageLifecycleHostingTests {
    private final class FakeMachine {}

    private static func specification(kind: VMShimProtocol.Specification.Kind = .storage) -> VMShimProtocol.Specification {
        var specification = VMShimProtocol.Specification(
            containerID: "storage", generation: 1, token: "token", kernelPath: "/kernel",
            initialRamdiskPath: "/initramfs", rootDiskPath: "/root.ext4", cpus: 1,
            memoryBytes: 512 << 20, macAddress: "02:ce:00:00:00:02", bindShares: [],
            socketPath: "/tmp/cengine-lifecycle-hosting.sock", logPath: "/tmp/cengine-lifecycle-hosting.log",
            shimLaunchUUID: UUID().uuidString.lowercased())
        specification.kind = kind
        return specification
    }

    @Test func openNeverRequestsFreshInitialization() throws {
        var fresh = 0, held = 0
        try RawContainerVirtualMachine.admitLifecycleDisk((), mode: .open,
            fresh: { fresh += 1 }, held: { held += 1 })
        #expect(fresh == 0 && held == 1)
        try RawContainerVirtualMachine.admitLifecycleDisk((), mode: .initialize,
            fresh: { fresh += 1 }, held: { held += 1 })
        #expect(fresh == 1 && held == 1)
        // A failing fresh capability can never be reached on .open.
        struct Refused: Error {}
        try RawContainerVirtualMachine.admitLifecycleDisk((), mode: .open,
            fresh: { throw Refused() }, held: {})
        #expect(throws: Refused.self) {
            try RawContainerVirtualMachine.admitLifecycleDisk((), mode: .initialize, fresh: { throw Refused() }, held: {})
        }
        #expect(RawContainerVirtualMachine.StorageLifecycleDiskMode.open.bootstrapPolicy == .requireInitializedStorage)
        #expect(RawContainerVirtualMachine.StorageLifecycleDiskMode.initialize.bootstrapPolicy == .journalDriven)
        #expect(RawStorageLifecycleShim.diskMode(for: .open) == .open)
        #expect(RawStorageLifecycleShim.diskMode(for: .initialize) == .initialize)
    }

    @Test func lifecycleHostingRejectsV1StorageOperations() throws {
        let lifecycle = Self.specification()
        for operation: VMShimProtocol.Operation in [.boot, .workloadStorageBoot] {
            #expect(throws: EngineError.self) {
                try VMShimServer.requireLifecycleHostingAdmission(operation, specification: lifecycle)
            }
            try VMShimServer.requireLifecycleHostingAdmission(operation, specification: Self.specification(kind: .container))
        }
        for operation: VMShimProtocol.Operation in [.status, .stop, .shutdown] {
            try VMShimServer.requireLifecycleHostingAdmission(operation, specification: lifecycle)
        }
    }

    @Test func enrolledOwnerRefusesTokenControlIncludingStopAndShutdown() throws {
        let lifecycle = Self.specification()
        for operation: VMShimProtocol.Operation in [.stop, .shutdown, .pause, .resume] {
            #expect(throws: EngineError.self) {
                try VMShimServer.requireLifecycleHostingAdmission(operation, specification: lifecycle, enrolled: true)
            }
        }
        try VMShimServer.requireLifecycleHostingAdmission(.status, specification: lifecycle, enrolled: true)
        try VMShimServer.requireLifecycleHostingAdmission(.configureFabric, specification: lifecycle, enrolled: true)
        try VMShimServer.requireLifecycleHostingAdmission(.stop, specification: Self.specification(kind: .container), enrolled: true)
    }

    @Test(arguments: [false, true])
    func tokenRouteIsAnExplicitInfrastructureAllowlist(enrolled: Bool) throws {
        let lifecycle = Self.specification()
        for operation in VMShimProtocol.Operation.allCases {
            let allowed = operation == .status || operation == .configureFabric ||
                (!enrolled && (operation == .stop || operation == .shutdown))
            if allowed { try VMShimServer.requireLifecycleHostingAdmission(operation, specification: lifecycle, enrolled: enrolled) }
            else {
                #expect(throws: EngineError.self) {
                    try VMShimServer.requireLifecycleHostingAdmission(operation, specification: lifecycle, enrolled: enrolled)
                }
            }
        }
    }
    @Test func malformedLifecycleRoutingClosesWithoutTokenBearingError() {
        let lifecycle = Self.specification()
        #expect(VMShimServer.requiresBoundedInitialFrame(lifecycle))
        #expect(VMShimServer.silentlyClosesUnauthenticatedFailure(lifecycle, authenticated: false))
        #expect(!VMShimServer.silentlyClosesUnauthenticatedFailure(lifecycle, authenticated: true))
    }
    @Test func resourceCompletionCannotPublishOwnerAfterTokenStop() throws {
        try VMShimServer.requireLifecycleHostingPublication(state: .starting, stopping: false)
        for state: VMShimProtocol.State in [.created, .running, .stopping, .stopped, .failed] {
            #expect(throws: EngineError.self) { try VMShimServer.requireLifecycleHostingPublication(state: state, stopping: false) }
        }
        #expect(throws: EngineError.self) { try VMShimServer.requireLifecycleHostingPublication(state: .starting, stopping: true) }
    }
    @Test(arguments: [false, true])
    func tokenStopJoinsHostPublicationBeforeTeardown(duringBind: Bool) async throws {
        let gate = VMShimBootGate(), machineOwner = VMShimMachineOwner<FakeMachine>()
        let control = StorageLifecycleControlLifetime()
        let machine = FakeMachine()
        machineOwner.machine = machine
        var state: VMShimProtocol.State = .starting
        var resumeWorker: CheckedContinuation<Void, Never>?
        var published = false, bound = false, started = false, closed = false, stopped = false
        let startup = Task {
            try await gate.boot {
                try await VMShimServer.publishLifecycleHost(construct: {
                    if !duringBind { await withCheckedContinuation { resumeWorker = $0 } }
                    return 1
                }, admit: {
                    try VMShimServer.requireLifecycleHostingPublication(state: state, stopping: gate.isStopping)
                    try machineOwner.requireCurrent(machine)
                    try control.withAdmission {}
                }, publish: { _ in published = true }, bind: {
                    if duringBind { await withCheckedContinuation { resumeWorker = $0 } }
                    bound = true
                }, start: { _ in started = true }, close: { _ in closed = true })
            }
        }
        while resumeWorker == nil { await Task.yield() }
        try control.reserveTokenStop()
        let stop = Task {
            try await gate.stop(willStop: { state = .stopping }) {
                // A cancelled worker must settle and its server must close before
                // teardown is allowed to release the VM and its disk leases.
                #expect(closed && !started)
                try await machineOwner.stopAndRelease(stop: { _ in stopped = true })
                state = .stopped
            }
        }
        while !gate.isStopping { await Task.yield() }
        #expect(!stopped && machineOwner.machine === machine)
        #expect(published == duringBind && !bound && !started)
        resumeWorker?.resume()
        await #expect(throws: CancellationError.self) { try await startup.value }
        try await stop.value
        #expect(closed && stopped && !started && machineOwner.machine == nil)
        #expect(published == duringBind && bound == duringBind)
        #expect(state == .stopped)
    }

    @Test(arguments: [false, true])
    func terminalOwnerCannotPublishOrStartEvenBeforeStopTaskBegins(duringBind: Bool) async throws {
        let control = StorageLifecycleControlLifetime()
        var published = false, bound = false, started = false, closed = false
        await #expect(throws: (any Error).self) {
            try await VMShimServer.publishLifecycleHost(construct: {
                // Token admission can close control before bootGate.stop runs.
                if !duringBind { try control.reserveTokenStop() }
                return 1
            }, admit: {
                try VMShimServer.requireLifecycleHostingPublication(state: .starting, stopping: false)
                try control.withAdmission {}
            }, publish: { _ in published = true }, bind: {
                bound = true
                if duringBind { try control.reserveTokenStop() }
            }, start: { _ in started = true }, close: { _ in closed = true })
        }
        #expect(closed && !started)
        #expect(published == duringBind && bound == duringBind)
    }

    @Test func completedHostPublicationDoesNotTieEnrolledMachineToDaemonEOF() async throws {
        let gate = VMShimBootGate(), machineOwner = VMShimMachineOwner<FakeMachine>()
        let control = StorageLifecycleControlLifetime(), machine = FakeMachine()
        machineOwner.machine = machine
        var published = false, bound = false, started = false, closed = false
        try await gate.boot {
            try await VMShimServer.publishLifecycleHost(construct: { 1 }, admit: {
                try control.withAdmission {}
            }, publish: { _ in published = true }, bind: { bound = true },
            start: { _ in
                #expect(published && bound)
                started = true
            }, close: { _ in closed = true })
        }
        try control.beginEnrollment(); try control.enroll()
        // EOF only fences control after ROOT enrollment; the startup transaction
        // is already complete and cannot turn it into VM/DATA teardown.
        #expect(control.detach() && control.preservesOwner)
        #expect(published && bound && started && !closed && !gate.isStopping)
        #expect(machineOwner.machine === machine)
    }

    @Test func lifecycleNeverAdmitsTokenPauseOrResumeEvenBeforeEnrollment() {
        for operation: VMShimProtocol.Operation in [.pause, .resume] {
            #expect(throws: EngineError.self) {
                try VMShimServer.requireLifecycleHostingAdmission(operation, specification: Self.specification())
            }
        }
    }

    @Test func enrollmentPendingReservesAgainstTokenStopAndNeverReopens() throws {
        let pending = StorageLifecycleControlLifetime()
        try pending.beginEnrollment()
        #expect(throws: (any Error).self) { try pending.reserveTokenStop() }
        #expect(!pending.isEnrolled)
        pending.detach() // failed enrollment is terminal
        #expect(throws: (any Error).self) { try pending.enroll() }
        #expect(throws: (any Error).self) { try pending.beginEnrollment() }
        #expect(throws: (any Error).self) { try pending.reserveTokenStop() }
        let stopped = StorageLifecycleControlLifetime()
        try stopped.reserveTokenStop()
        #expect(throws: (any Error).self) { try stopped.beginEnrollment() }
    }

    @Test func privateStopReservationReleasesAdmissionBeforeFencing() throws {
        let control = StorageLifecycleControlLifetime()
        try control.beginEnrollment(); try control.enroll()
        try control.reservePrivateStop()
        let joined = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            // Off-main ROOT fence can acquire admission and complete even while
            // the private-stop caller has not yet begun MainActor teardown.
            #expect(control.detach())
            joined.signal()
        }
        #expect(joined.wait(timeout: .now() + 2) == .success)
        #expect(throws: (any Error).self) { try control.captureGeneration() }
        #expect(throws: (any Error).self) { try control.reservePrivateStop() }
        #expect(control.detach(revokeTransport: false))
    }

    @Test func failureDetachAndRootPublicationHaveOneAtomicDecision() throws {
        for _ in 0..<100 {
            let control = StorageLifecycleControlLifetime()
            try control.beginEnrollment()
            let joined = DispatchSemaphore(value: 0)
            DispatchQueue.global().async {
                try? control.enroll()
                joined.signal()
            }
            let preserve = control.detach()
            #expect(joined.wait(timeout: .now() + 2) == .success)
            // Enrollment either won and must be preserved, or can never publish
            // after the failure chose teardown. No read-then-terminate interval.
            #expect(preserve == control.isEnrolled)
            #expect(throws: (any Error).self) { try control.enroll() }
        }
    }

    @Test func rootReplyPublishesEnrollmentWithoutMainActorHop() throws {
        let control = StorageLifecycleControlLifetime()
        try control.beginEnrollment()
        let replied = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            do { try control.enroll() } catch { Issue.record("ROOT reply publication failed") }
            replied.signal()
        }
        // MainActor intentionally blocked until the authenticated-reply seam publishes.
        #expect(replied.wait(timeout: .now() + 2) == .success)
        #expect(control.isEnrolled)
        #expect(throws: (any Error).self) { try control.reserveTokenStop() }
        #expect(control.detach() && control.preservesOwner)
    }

    @Test func lifecycleUsesLifecycleGuestModeAndClosedDecode() throws {
        let lifecycleArguments = try VMShimServer.bootstrapKernelArguments(Self.specification())
        #expect(lifecycleArguments.contains("cengine.storage_mode=lifecycle"))
        #expect(!lifecycleArguments.contains("cengine.storage_mode=managed"))
        let specification = Self.specification()
        let data = try JSONEncoder().encode(specification)
        #expect(try JSONDecoder().decode(VMShimProtocol.Specification.self, from: data) == specification)
        let fields = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(fields["storageStartupMode"] == nil && fields["fileSystemSocketPath"] == nil)
    }

    @Test func lifecycleDescriptorIsRequiredExactAndExclusive() throws {
        #expect(throws: EngineError.self) {
            _ = try VMShimServer.inheritLifecycleDescriptor(nil, specification: Self.specification())
        }
        #expect(try VMShimServer.inheritLifecycleDescriptor(nil, specification: Self.specification(kind: .container)) == nil)
        // Non-lifecycle specs refuse any descriptor; lifecycle refuses anything but FD4.
        #expect(throws: EngineError.self) {
            _ = try VMShimServer.inheritLifecycleDescriptor(VMShimClient.storageLifecycleDescriptor,
                specification: Self.specification(kind: .container))
        }
        #expect(throws: EngineError.self) {
            _ = try VMShimServer.inheritLifecycleDescriptor(5, specification: Self.specification())
        }
        #expect(throws: EngineError.self) {
            _ = try VMShimServer.inheritLifecycleDescriptor(VMShimClient.storageLifecycleDescriptor,
                specification: Self.specification(kind: .container))
        }
        #expect(VMShimClient.storageDiskDescriptor == 3 && VMShimClient.storageLifecycleDescriptor == 4)
    }

    @Test func singleMachineHostingIsOneShotAndBoundToOwner() throws {
        let owner = VMShimMachineOwner<FakeMachine>()
        let hosting = VMShimLifecycleHosting<FakeMachine>()
        let machine = FakeMachine(), other = FakeMachine()
        try hosting.host(machine, owner: owner)
        #expect(owner.machine === machine && hosting.phase == .hosting)
        #expect(throws: EngineError.self) { try hosting.host(other, owner: owner) }
        #expect(owner.machine === machine)
        #expect(!hosting.ready(other, owner: owner))
        #expect(hosting.ready(machine, owner: owner) && hosting.phase == .ready)
        #expect(!hosting.ready(machine, owner: owner))
        #expect(!hosting.terminate(other))
        #expect(hosting.terminate(machine) && hosting.phase == .terminal)
        #expect(!hosting.terminate(machine) && !hosting.terminate(nil))

        // An owner already tracking a different machine cannot be re-hosted.
        let occupied = VMShimMachineOwner<FakeMachine>()
        occupied.machine = other
        #expect(throws: EngineError.self) { try VMShimLifecycleHosting<FakeMachine>().host(machine, owner: occupied) }
        // Failure before any machine terminates exactly once.
        let early = VMShimLifecycleHosting<FakeMachine>()
        #expect(early.terminate(nil) && !early.terminate(nil))
    }

    @Test func initializerExitWaitsForFullStopJoinAndIsOneShot() async throws {
        let owner = VMShimMachineOwner<FakeMachine>()
        owner.machine = FakeMachine()
        let abort = StorageLifecycleFreshAbort(), guestExit = StorageLifecycleGuestExit()
        let control = StorageLifecycleControlLifetime(), exit = VMShimInitializerExit()
        let bootGate = VMShimBootGate()
        guestExit.guestDidStop()
        abort.begin(exit: guestExit, close: { _ in }, fallback: { Issue.record("unexpected force") })
        #expect(await abort.task?.value == true)
        var exits: [Int32] = [], stops = 0, joins = 0
        var finishCleanup: CheckedContinuation<Void, Never>?
        exit.onExit = { code in
            #expect(owner.machine == nil)
            exits.append(code)
        }
        let join = {
            try await exit.joinStop({
                joins += 1
                try await bootGate.stop {
                    stops += 1
                    try await owner.stopAndRelease(stop: { _ in
                        #expect(await abort.task?.value == true)
                    }, afterStop: {
                        await withCheckedContinuation { finishCleanup = $0 }
                    })
                }
            }, eligible: { abort.permitsProcessExit(control: control, privateStopRequested: false) },
            machineRetained: { owner.machine != nil })
        }
        let first = Task { try await join() }
        while finishCleanup == nil { await Task.yield() }
        // A positive Guest callback and a completed abort are NOT full teardown.
        #expect(exits.isEmpty && owner.machine != nil && bootGate.isStopping)
        let reentrant = Task { try await join() }
        while joins < 2 { await Task.yield() }
        #expect(exits.isEmpty)
        finishCleanup?.resume()
        try await first.value
        try await reentrant.value
        #expect(owner.machine == nil && stops == 1)
        #expect(exits == [EXIT_FAILURE])
        // Repeated completion cannot deliver a second process-exit action.
        try await exit.joinStop({}, eligible: { true }, machineRetained: { false })
        #expect(exits == [EXIT_FAILURE])
    }

    @Test(arguments: [false, true])
    func initializerExitRefusesFailedStopOrSurroundingCleanup(failCleanup: Bool) async {
        let owner = VMShimMachineOwner<FakeMachine>(), machine = FakeMachine()
        owner.machine = machine
        let exit = VMShimInitializerExit()
        var exits = 0
        exit.onExit = { _ in exits += 1 }
        await #expect(throws: CancellationError.self) {
            try await exit.joinStop({
                try await owner.stopAndRelease(stop: { _ in
                    if !failCleanup { throw CancellationError() }
                }, afterStop: { throw CancellationError() })
            }, eligible: { true }, machineRetained: { owner.machine != nil })
        }
        #expect(exits == 0 && owner.machine === machine)
    }

    @Test(arguments: ["ordinary", "enrolled", "privateStop", "tokenStop", "retainedMachine"])
    func initializerExitGuardsPreserveOwnersAndReplies(blocker: String) async throws {
        let abort = StorageLifecycleFreshAbort(), control = StorageLifecycleControlLifetime()
        let exit = VMShimInitializerExit(), owner = VMShimMachineOwner<FakeMachine>()
        if blocker != "ordinary" {
            abort.begin(exit: StorageLifecycleGuestExit(), neverStarted: true,
                        close: { _ in }, fallback: {})
            _ = await abort.task?.value
        }
        if blocker == "enrolled" { try control.beginEnrollment(); try control.enroll() }
        if blocker == "retainedMachine" { owner.machine = FakeMachine() }
        exit.tokenStopRequested = blocker == "tokenStop"
        var exits = 0
        exit.onExit = { _ in exits += 1 }
        try await exit.joinStop({}, eligible: {
            abort.permitsProcessExit(control: control, privateStopRequested: blocker == "privateStop")
        }, machineRetained: { owner.machine != nil })
        #expect(exits == 0)
        if blocker == "enrolled" {
            #expect(control.detach() && control.preservesOwner)
        }
    }

    @Test func initializerExitRechecksAdmissionAfterSuspendedStop() async throws {
        let abort = StorageLifecycleFreshAbort(), control = StorageLifecycleControlLifetime()
        abort.begin(exit: StorageLifecycleGuestExit(), neverStarted: true, close: { _ in }, fallback: {})
        let exit = VMShimInitializerExit()
        var exits = 0
        exit.onExit = { _ in exits += 1 }
        try await exit.joinStop({
            await Task.yield()
            exit.tokenStopRequested = true
        }, eligible: { abort.permitsProcessExit(control: control, privateStopRequested: false) },
        machineRetained: { false })
        #expect(exits == 0)
    }

    @Test func privateStopExitWaitsForReplyEndAndPositiveJoinedRelease() async throws {
        let control = StorageLifecycleControlLifetime(), exit = VMShimInitializerExit()
        let generation = try control.captureGeneration()
        try control.beginEnrollment(); try control.enroll()
        try control.reservePrivateStop(generation)
        var reply = StorageLifecycleStopReplyLifetime()
        try reply.begin(generation)
        let owner = VMShimMachineOwner<FakeMachine>(), gate = VMShimBootGate()
        owner.machine = FakeMachine()
        var exits: [Int32] = [], joins = 0, stops = 0
        exit.onExit = { exits.append($0) }
        // Even an otherwise completed stop cannot retire the authenticated peer
        // while its client still needs post-response native authentication.
        try await exit.joinStop({}, eligible: { reply.permitsProcessExit },
                                machineRetained: { false }, exitStatus: { EXIT_SUCCESS })
        #expect(exits.isEmpty)
        #expect(reply.finish(generation) == true)
        var finishStop: CheckedContinuation<Void, Never>?
        var finishCleanup: CheckedContinuation<Void, Never>?
        let join = {
            try await exit.joinStop({
                joins += 1
                try await gate.stop {
                    stops += 1
                    try await owner.stopAndRelease(stop: { _ in
                        await withCheckedContinuation { finishStop = $0 }
                    }, afterStop: {
                        await withCheckedContinuation { finishCleanup = $0 }
                    })
                }
            }, eligible: { reply.permitsProcessExit }, machineRetained: { owner.machine != nil },
            exitStatus: { EXIT_SUCCESS })
        }
        let first = Task { try await join() }
        while finishStop == nil { await Task.yield() }
        #expect(exits.isEmpty && owner.machine != nil)
        finishStop?.resume()
        while finishCleanup == nil { await Task.yield() }
        #expect(exits.isEmpty && owner.machine != nil)
        let reentrant = Task { try await join() }
        while joins < 2 { await Task.yield() }
        #expect(exits.isEmpty)
        finishCleanup?.resume()
        try await first.value
        try await reentrant.value
        #expect(owner.machine == nil && stops == 1 && exits == [EXIT_SUCCESS])
        #expect(reply.finish(generation) == false)
        try await exit.joinStop({}, eligible: { reply.permitsProcessExit },
                                machineRetained: { false }, exitStatus: { EXIT_SUCCESS })
        #expect(exits == [EXIT_SUCCESS])
    }

    @Test(arguments: ["stopFailure", "cleanupFailure", "retainedMachine", "ordinaryEOF"])
    func privateStopExitRequiresReplyAndSuccessfulRelease(blocker: String) async throws {
        let control = StorageLifecycleControlLifetime(), exit = VMShimInitializerExit()
        let generation = try control.captureGeneration()
        try control.beginEnrollment(); try control.enroll()
        var reply = StorageLifecycleStopReplyLifetime()
        if blocker != "ordinaryEOF" {
            try control.reservePrivateStop(generation)
            try reply.begin(generation)
            #expect(reply.finish(generation) == true)
        } else {
            #expect(control.detach(generation) == .preserved)
            #expect(!reply.finish(generation) && control.preservesOwner)
        }
        let owner = VMShimMachineOwner<FakeMachine>(), machine = FakeMachine()
        owner.machine = machine
        var exits = 0
        exit.onExit = { _ in exits += 1 }
        let join = {
            try await exit.joinStop({
                if blocker == "stopFailure" || blocker == "cleanupFailure" {
                    try await owner.stopAndRelease(stop: { _ in
                        if blocker == "stopFailure" { throw CancellationError() }
                    }, afterStop: { throw CancellationError() })
                }
            }, eligible: { reply.permitsProcessExit },
            // Test EOF eligibility independently of the machine-retention guard.
            machineRetained: { blocker != "ordinaryEOF" && owner.machine != nil },
            exitStatus: { EXIT_SUCCESS })
        }
        if blocker == "stopFailure" || blocker == "cleanupFailure" {
            await #expect(throws: CancellationError.self) { try await join() }
        } else { try await join() }
        #expect(exits == 0 && owner.machine === machine)
    }

    @Test func initializerExitHasNoExecutableActionByDefault() async throws {
        let exit = VMShimInitializerExit()
        #expect(exit.onExit == nil)
        try await exit.joinStop({}, eligible: { true }, machineRetained: { false })
    }

    @Test func lifecycleSocketPairFlagsAndCleanup() throws {
        let pair = try VMShimClient.makeLifecycleSocketPair()
        #expect(fcntl(pair.parent, F_GETFD) & FD_CLOEXEC != 0)
        #expect(fcntl(pair.child, F_GETFD) & FD_CLOEXEC != 0)
        #expect(fcntl(pair.parent, F_GETFL) & O_NONBLOCK != 0)
        #expect(fcntl(pair.child, F_GETFL) & O_NONBLOCK == 0)
        #expect(Darwin.close(pair.child) == 0 && Darwin.close(pair.parent) == 0)
        #expect(fcntl(pair.parent, F_GETFD) == -1)
    }

    @Test func hostBootstrapFreezesMountOnlyBeforeDiskConstruction() throws {
        let f = try ColdContractFixture()
        let host = StorageLifecycleShimProtocol.HostBootstrap(profile: StorageLifecycleShimProtocol.HostBootstrap.version,
            diskMode: .open, rootPublicKey: f.prepare.mountedGreeting.rootPublicKey,
            binding: f.prepare.mountedGreeting.binding)
        let bytes = try StorageLifecycleShimProtocol.encodeHost(host)
        let decoded = try StorageLifecycleShimProtocol.decodeHost(bytes)
        #expect(decoded == host && decoded.diskMode.policy == .requireInitializedStorage)
        #expect(StorageLifecycleShimProtocol.HostBootstrap.DiskMode.initialize.policy == .journalDriven)
        var object = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        object.removeValue(forKey: "diskMode")
        #expect(throws: (any Error).self) {
            try StorageLifecycleShimProtocol.decodeHost(JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]))
        }
        let reply = StorageLifecycleShimProtocol.Frame(sequence: 1, operation: .prepareCold, reply: true,
            coldGreeting: f.prepare.mountedGreeting)
        #expect(try StorageLifecycleShimProtocol.decode(StorageLifecycleShimProtocol.encode(reply)).coldGreeting == f.prepare.mountedGreeting)
        var wrong = reply
        wrong.configuration = nil
        wrong.greeting = try .init(channelID: UUID().uuidString.lowercased(), daemonUniqueID: 10,
            rootPublicKey: host.rootPublicKey, store: host.binding.store,
            shimLaunchUUID: f.prepare.mountedGreeting.launch.shimLaunchUUID,
            guestBootNonce: f.prepare.mountedGreeting.bootBinding.guestBootNonce,
            operationUUID: UUID().uuidString.lowercased(), ext4UUID: host.binding.ext4UUID,
            bytes: host.binding.bytes, initramfsSHA256: f.prepare.mountedGreeting.launch.initramfsSHA256,
            device: f.prepare.mountedGreeting.heldBackingIdentity.device, inode: host.binding.backing.inode, volumeUUID: host.binding.backing.volumeUUID)
        #expect(throws: (any Error).self) { try StorageLifecycleShimProtocol.encode(wrong) }
    }

    @Test func hostBootstrapRejectsMalformedFrames() {
        #expect(throws: (any Error).self) { _ = try StorageLifecycleShimProtocol.decodeHost(Data("{}".utf8)) }
        #expect(throws: (any Error).self) { _ = try StorageLifecycleShimProtocol.decodeHost(Data()) }
        #expect(StorageLifecycleShimProtocol.HostBootstrap.bound != Data("lifecycle-v2-native-v1:bound".utf8))
    }
}
#endif
