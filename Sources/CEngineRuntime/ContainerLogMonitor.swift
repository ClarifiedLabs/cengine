import Foundation

final class ContainerLogMonitor: @unchecked Sendable {
    private let stdoutURL: URL
    private let stderrURL: URL
    private let inputURL: URL
    private let bridge: ContainerIOBridge
    private let lock = NSLock()
    private var offsets: [URL: UInt64] = [:]
    private var task: Task<Void, Never>?
    private var inputTask: Task<Void, Never>?

    init(directory: URL, bridge: ContainerIOBridge) {
        stdoutURL = directory.appending(path: "stdout")
        stderrURL = directory.appending(path: "stderr")
        inputURL = directory.appending(path: "stdin")
        self.bridge = bridge
    }

    init(stdoutURL: URL, stderrURL: URL, inputURL: URL, bridge: ContainerIOBridge) {
        self.stdoutURL = stdoutURL; self.stderrURL = stderrURL; self.inputURL = inputURL; self.bridge = bridge
    }

    func start(atEnd: Bool = false) {
        guard task == nil else { return }
        if atEnd {
            for url in [stdoutURL, stderrURL] {
                if let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize {
                    offsets[url] = UInt64(size)
                }
            }
        }
        task = Task.detached { [weak self] in
            while !Task.isCancelled {
                self?.drain(self?.stdoutURL, stream: .stdout)
                self?.drain(self?.stderrURL, stream: .stderr)
                try? await Task.sleep(for: .milliseconds(25))
            }
        }
        let input = inputURL
        inputTask = Task.detached { [bridge] in
            defer { FileManager.default.createFile(atPath: input.appendingPathExtension("closed").path, contents: nil) }
            for await data in bridge.stream() {
                do {
                    if !FileManager.default.fileExists(atPath: input.path) { FileManager.default.createFile(atPath: input.path, contents: nil) }
                    let file = try FileHandle(forWritingTo: input); try file.seekToEnd(); try file.write(contentsOf: data); try file.close()
                } catch { return }
            }
        }
    }

    func stop(finishOutput: Bool = true) {
        task?.cancel(); inputTask?.cancel(); task = nil; inputTask = nil
        drain(stdoutURL, stream: .stdout); drain(stderrURL, stream: .stderr)
        if finishOutput { bridge.finishOutput() }
    }

    func drain(
        _ url: URL?, stream: ContainerIOBridge.OutputStream,
        didReadOffset: @Sendable () -> Void = {}
    ) {
        guard let url else { return }
        lock.lock()
        defer { lock.unlock() }
        guard let handle = try? FileHandle(forReadingFrom: url) else { return }
        let offset = offsets[url] ?? 0
        didReadOffset()
        do {
            try handle.seek(toOffset: offset)
            let data = try handle.readToEnd() ?? Data()
            let next = try handle.offset(); try handle.close()
            offsets[url] = next
            if !data.isEmpty { try bridge.writer(stream).write(data) }
        } catch { try? handle.close() }
    }

}
