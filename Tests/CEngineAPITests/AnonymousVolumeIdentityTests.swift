import CEngineCore
@testable import CEngineRuntime
@testable import CEngineAPI
import Foundation
import Testing

@Suite struct AnonymousVolumeIdentityTests {
    private actor Gate {
        private var entered = false
        private var observer: CheckedContinuation<Void, Never>?
        private var continuation: CheckedContinuation<Void, Never>?
        func pause() async {
            entered = true
            observer?.resume(); observer = nil
            await withCheckedContinuation { continuation = $0 }
        }
        func wait() async {
            if !entered { await withCheckedContinuation { observer = $0 } }
        }
        func release() { continuation?.resume(); continuation = nil }
    }

    private actor Backend: ContainerBackend {
        var preparations = 0
        func pullImage(_: String, platform _: String) async throws {}
        func prepare(_: ContainerRecord) async throws { preparations += 1 }
        func start(_ container: ContainerRecord) async throws -> [PortBinding] { container.ports }
        func stop(_: ContainerRecord, timeoutSeconds _: Int) async throws -> Int32 { 0 }
        func wait(_: ContainerRecord) async throws -> Int32 { 0 }
        func cleanupExecution(_: ContainerRecord) async throws {}
        func delete(_: ContainerRecord) async throws {}
    }

    @Test func removedAnonymousVolumeCannotBeRecreatedByContainerPublication() async throws {
        let root = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let gate = Gate()
        let backend = Backend()
        let runtime = try await EngineRuntime(root: root, backend: backend)
        let router = DockerRouter(runtime: runtime, root: root,
                                  afterAnonymousVolumeCreation: { await gate.pause() })
        // Pause after anonymous create returned its exact V to the router, with
        // no storage-publication lock held. No timing sleeps or mocked identity.
        let request = APIRequest(method: .POST, uri: "/v1.55/containers/create?name=anonymous-race",
            body: Data(#"{"Image":"alpine","Cmd":["true"],"Volumes":{"/alpha":{},"/beta":{}},"HostConfig":{"NetworkMode":"none"}}"#.utf8))
        let creation = Task { await router.route(request) }
        await gate.wait()
        do {
            let first = try #require(await runtime.listVolumes().first)
            #expect(first.anonymous == true)
            #expect(first.instanceID != nil)
            // The first volume has no container reference yet. Removal is legal,
            // but the outstanding create must not silently mint a replacement V.
            try await runtime.removeVolume(first.name, force: false)
            await gate.release()
            let response = await creation.value
            #expect(response.status == .conflict)
            #expect(await backend.preparations == 0)
            #expect(await runtime.listContainers(all: true).isEmpty)
            #expect(await runtime.listVolumes().allSatisfy { $0.name != first.name })
        } catch {
            await gate.release()
            _ = await creation.value
            throw error
        }
    }
}
