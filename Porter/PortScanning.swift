import Foundation
import os

// MARK: - Protocol

protocol PortScanning: Sendable {
    func scan() async -> ScanResult
}

// MARK: - Live Scanner

struct LivePortScanner: PortScanning {
    private let log = Log.scanner

    private static let branchTTL: TimeInterval = 30
    private static let cache = CacheStore()
    private static let processTracker = ProcessTracker()
    private static let allowedFallbackProcessNames: Set<String> = [
        "air",
        "beam.smp",
        "bun",
        "deno",
        "elixir",
        "erl",
        "go",
        "gunicorn",
        "java",
        "mix",
        "node",
        "php",
        "puma",
        "python",
        "python3",
        "reflex",
        "ruby",
        "uvicorn"
    ]

    func scan() async -> ScanResult {
        let start = Date()
        let previousPorts: [ActivePort] = []

        do {
            let ports = try await performScan()
            let diag = ScanDiagnostics(
                duration: Date().timeIntervalSince(start),
                portsFound: ports.count,
                dataSource: "lsof",
                timestamp: Date()
            )
            log.info("Scan complete: \(ports.count) ports in \((diag.duration * 1000).formatted(.number.precision(.fractionLength(0))))ms")
            return .success(ports, diag)
        } catch let error as ScanError {
            log.error("Scan failed: \(error.localizedDescription)")
            return .failure(error, previousPorts)
        } catch {
            log.error("Scan failed unexpectedly: \(error.localizedDescription)")
            return .failure(.lsofFailed(error.localizedDescription), previousPorts)
        }
    }

    private func performScan() async throws -> [ActivePort] {
        let lsofOutput = try await runShell(
            "/usr/sbin/lsof", args: ["-iTCP", "-sTCP:LISTEN", "-n", "-P"],
            timeout: 10
        )

        let parsed = Self.parseLsofOutput(lsofOutput)
        if parsed.isEmpty {
            if Log.isVerbose { log.debug("lsof returned no listening ports") }
            return []
        }

        let pids = Set(parsed.map(\.pid))
        let hasContainerPorts = parsed.contains {
            Self.containerRuntimeName(for: $0.processName) != nil
                || Self.isLikelyContainerForwarder(processName: $0.processName)
        }
        async let cwdResult = resolveCWDs(pids: pids)
        async let startTimeResult = resolveStartTimes(pids: pids)
        let forwardedPorts = Set(parsed.compactMap { info -> UInt16? in
            Self.isLikelyContainerForwarder(processName: info.processName) ? info.port : nil
        })
        async let containerResult = resolveContainers(
            enabled: hasContainerPorts,
            forwardedPorts: forwardedPorts
        )
        let (cwds, startTimes, containers) = await (cwdResult, startTimeResult, containerResult)

        return await resolveProjects(parsed: parsed, cwds: cwds,
                                     startTimes: startTimes, containers: containers)
    }

    // MARK: - Container Resolution

    struct ContainerInfo: Sendable {
        let project: String   // compose project, devcontainer folder, or container name
        let service: String   // compose service or forwarded-port label
    }

    // Common install locations for the `docker`-compatible CLI. The same binary
    // works for Docker Desktop and OrbStack (which the active context points at).
    private static func dockerExecutable() -> String? {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser.path()
        let candidates = [
            "/usr/local/bin/docker",
            "/opt/homebrew/bin/docker",
            "\(home)/.orbstack/bin/docker",
            "/Applications/OrbStack.app/Contents/MacOS/xbin/docker",
            "/Applications/Docker.app/Contents/Resources/bin/docker",
        ]
        return candidates.first { fm.isExecutableFile(atPath: $0) }
    }

    private struct ContainerRow: Sendable {
        let name: String
        let portsField: String
        let projectName: String
        let serviceLabel: String
        let devContainerPorts: [UInt16: String]
    }

    /// Maps published host ports to their container's compose project/service by
    /// querying the container CLI. Best-effort: returns empty if no runtime ports
    /// were seen, the CLI is missing, or the daemon is unreachable.
    private func resolveContainers(enabled: Bool, forwardedPorts: Set<UInt16>) async -> [UInt16: ContainerInfo] {
        guard enabled, let docker = Self.dockerExecutable() else { return [:] }
        let format = #"{{.Names}}\t{{.Ports}}\t{{.Label "com.docker.compose.project"}}\t{{.Label "com.docker.compose.service"}}\t{{.Label "devcontainer.local_folder"}}\t{{.Label "devcontainer.metadata"}}"#
        guard let output = try? await runShell(
            docker, args: ["ps", "--no-trunc", "--format", format],
            timeout: 5
        ) else {
            if Log.isVerbose { log.debug("docker ps lookup failed or timed out") }
            return [:]
        }

        let rows = Self.parseContainerRows(output)
        var result: [UInt16: ContainerInfo] = [:]

        for row in rows {
            for port in Self.parseContainerHostPorts(row.portsField) {
                let detail = row.devContainerPorts[port].flatMap { $0.isEmpty ? nil : $0 } ?? row.serviceLabel
                result[port] = ContainerInfo(project: row.projectName, service: detail)
            }

            for (port, label) in row.devContainerPorts where result[port] == nil {
                let detail = label.isEmpty ? row.serviceLabel : label
                result[port] = ContainerInfo(project: row.projectName, service: detail)
            }
        }

        var unresolvedForwardedPorts = Set(forwardedPorts.filter { result[$0] == nil })
        if !unresolvedForwardedPorts.isEmpty {
            for row in rows where result.values.contains(where: { $0.project == row.projectName }) == false {
                let hasDeclaredPorts = !Self.parseContainerHostPorts(row.portsField).isEmpty
                    || !row.devContainerPorts.isEmpty
                if hasDeclaredPorts {
                    continue
                }

                let listeningPorts = await resolveContainerListeningPorts(docker: docker, containerName: row.name)
                let matched = listeningPorts.intersection(unresolvedForwardedPorts)
                if matched.isEmpty {
                    continue
                }

                for port in matched {
                    result[port] = ContainerInfo(project: row.projectName, service: row.serviceLabel)
                }
                unresolvedForwardedPorts.subtract(matched)
                if unresolvedForwardedPorts.isEmpty {
                    break
                }
            }
        }

        return result
    }

    /// Parses the tab-separated `docker ps` output into a host-port → container map.
    static func parseContainerOutput(_ output: String) -> [UInt16: ContainerInfo] {
        let rows = parseContainerRows(output)
        var result: [UInt16: ContainerInfo] = [:]
        for row in rows {
            for port in parseContainerHostPorts(row.portsField) {
                let detail = row.devContainerPorts[port].flatMap { $0.isEmpty ? nil : $0 } ?? row.serviceLabel
                result[port] = ContainerInfo(project: row.projectName, service: detail)
            }

            for (port, label) in row.devContainerPorts where result[port] == nil {
                let detail = label.isEmpty ? row.serviceLabel : label
                result[port] = ContainerInfo(project: row.projectName, service: detail)
            }
        }
        return result
    }

    private static func parseContainerRows(_ output: String) -> [ContainerRow] {
        var rows: [ContainerRow] = []
        for line in output.split(separator: "\n", omittingEmptySubsequences: true) {
            let cols = line.components(separatedBy: "\t")
            guard cols.count >= 2 else { continue }
            let name = cols[0].trimmingCharacters(in: .whitespaces)
            let portsField = cols[1]
            let projectLabel = cols.count > 2 ? cols[2].trimmingCharacters(in: .whitespaces) : ""
            let serviceLabel = cols.count > 3 ? cols[3].trimmingCharacters(in: .whitespaces) : ""
            let localFolder = cols.count > 4 ? cols[4].trimmingCharacters(in: .whitespaces) : ""
            let metadata = cols.count > 5 ? cols[5].trimmingCharacters(in: .whitespaces) : ""
            rows.append(
                ContainerRow(
                    name: name,
                    portsField: portsField,
                    projectName: containerProjectName(
                        containerName: name,
                        composeProject: projectLabel,
                        localFolder: localFolder
                    ),
                    serviceLabel: serviceLabel,
                    devContainerPorts: parseDevContainerForwardedPorts(metadata)
                )
            )
        }
        return rows
    }

    static func containerProjectName(containerName: String, composeProject: String, localFolder: String) -> String {
        if !composeProject.isEmpty {
            return composeProject
        }

        if !localFolder.isEmpty {
            let folderName = URL(filePath: localFolder).lastPathComponent
            if !folderName.isEmpty {
                return folderName
            }
        }

        return containerName
    }

    /// Extracts published host ports from a docker `Ports` field, e.g.
    /// "0.0.0.0:3000->3000/tcp, [::]:3000->3000/tcp" → [3000]. Unpublished
    /// ports like "8000/tcp" (no "->") are ignored.
    static func parseContainerHostPorts(_ portsField: String) -> [UInt16] {
        var seen = Set<UInt16>()
        var ports: [UInt16] = []
        for match in portsField.matches(of: #/:(\d{1,5})->/#) {
            guard let port = UInt16(match.1), seen.insert(port).inserted else { continue }
            ports.append(port)
        }
        return ports
    }

    static func parseDevContainerForwardedPorts(_ metadata: String) -> [UInt16: String] {
        guard !metadata.isEmpty,
              let data = metadata.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]
        else {
            return [:]
        }

        var result: [UInt16: String] = [:]
        for item in json {
            guard let portsAttributes = item["portsAttributes"] as? [String: Any] else { continue }
            for (portString, value) in portsAttributes {
                guard let port = UInt16(portString) else { continue }
                let label = (value as? [String: Any])?["label"] as? String ?? ""
                result[port] = label
            }
        }
        return result
    }

    private func resolveContainerListeningPorts(docker: String, containerName: String) async -> Set<UInt16> {
        guard let output = try? await runShell(
            docker,
            args: [
                "exec", containerName, "sh", "-lc",
                "ss -lntH 2>/dev/null || netstat -lnt 2>/dev/null",
            ],
            timeout: 3
        ) else {
            return []
        }
        return Self.parseNonLoopbackListeningPortsFromNetworkTools(output)
    }

    static func parseListeningPortsFromNetworkTools(_ output: String) -> Set<UInt16> {
        var result = Set<UInt16>()
        for line in output.split(separator: "\n", omittingEmptySubsequences: true) {
            for match in line.matches(of: #/:(\d{1,5})(?:\s|$)/#) {
                guard let port = UInt16(match.1), port >= 1024, port < 49152 else { continue }
                result.insert(port)
            }
        }
        return result
    }

    static func parseNonLoopbackListeningPortsFromNetworkTools(_ output: String) -> Set<UInt16> {
        var result = Set<UInt16>()
        let lines = output.split(separator: "\n", omittingEmptySubsequences: true)
        for line in lines {
            let fields = line.split(whereSeparator: { $0.isWhitespace })
            for field in fields {
                let token = String(field)
                guard let lastColon = token.lastIndex(of: ":") else { continue }
                let hostPart = String(token[..<lastColon]).trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
                let portPart = String(token[token.index(after: lastColon)...])
                guard let port = UInt16(portPart), port >= 1024, port < 49152 else { continue }
                if isLoopbackHost(hostPart) { continue }
                result.insert(port)
            }
        }
        return result
    }

    static func isLoopbackHost(_ host: String) -> Bool {
        let normalized = host.lowercased()
        if normalized == "localhost" || normalized == "::1" {
            return true
        }
        return normalized.hasPrefix("127.")
    }

    // MARK: - lsof Parsing (static for testability)

    struct ParsedPort: Sendable {
        let port: UInt16
        let pid: Int32
        let processName: String
    }

    static func parseLsofOutput(_ output: String) -> [ParsedPort] {
        var seen = Set<UInt16>()
        var results: [ParsedPort] = []

        let lines = output.split(separator: "\n", omittingEmptySubsequences: true)
        for line in lines.dropFirst() {
            let cols = line.split(separator: " ", omittingEmptySubsequences: true)
            guard cols.count >= 9 else { continue }
            let processName = String(cols[0])
            guard let pid = Int32(cols[1]) else { continue }

            let nameCol = String(cols[cols.count - 2])
            guard let colonIdx = nameCol.lastIndex(of: ":"),
                  let port = UInt16(nameCol[nameCol.index(after: colonIdx)...])
            else { continue }

            let stateCol = String(cols[cols.count - 1])
            guard stateCol == "(LISTEN)" else { continue }

            guard port >= 1024, port < 49152 else {
                if Log.isVerbose {
                    Log.scanner.debug("Skipping out-of-range port \(port)")
                }
                continue
            }

            guard seen.insert(port).inserted else { continue }
            results.append(ParsedPort(port: port, pid: pid, processName: processName))
        }

        return results.sorted { $0.port < $1.port }
    }

    // MARK: - CWD Resolution

    private func resolveCWDs(pids: Set<Int32>) async -> [Int32: String] {
        guard !pids.isEmpty else { return [:] }
        let pidList = pids.map(String.init).joined(separator: ",")
        guard let output = try? await runShell(
            "/usr/sbin/lsof", args: ["-a", "-p", pidList, "-d", "cwd", "-Fn"],
            timeout: 10
        ) else { return [:] }

        var result: [Int32: String] = [:]
        var currentPID: Int32?

        for line in output.split(separator: "\n") {
            if line.hasPrefix("p"), let pid = Int32(line.dropFirst()) {
                currentPID = pid
            } else if line.hasPrefix("n/"), let pid = currentPID {
                result[pid] = String(line.dropFirst())
            }
        }
        return result
    }

    // MARK: - Start Time Resolution

    private func resolveStartTimes(pids: Set<Int32>) async -> [Int32: Date] {
        guard !pids.isEmpty else { return [:] }
        let pidList = pids.map(String.init).joined(separator: ",")
        guard let output = try? await runShell(
            "/bin/ps", args: ["-p", pidList, "-o", "pid=,lstart="],
            timeout: 5,
            environment: ["LC_ALL": "C"]
        ) else { return [:] }

        var result: [Int32: Date] = [:]
        // ps lstart format: "Tue Mar  5 14:23:01 2026"
        let strategy = Date.ParseStrategy(
            format: "\(weekday: .abbreviated) \(month: .abbreviated) \(day: .twoDigits) \(hour: .twoDigits(clock: .twentyFourHour, hourCycle: .zeroBased)):\(minute: .twoDigits):\(second: .twoDigits) \(year: .defaultDigits)",
            locale: Locale(identifier: "en_US_POSIX"),
            timeZone: .current
        )
        for line in output.split(separator: "\n") {
            let parts = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
            guard parts.count == 2, let pid = Int32(parts[0]) else { continue }
            let normalized = parts[1]
                .split(separator: " ", omittingEmptySubsequences: true)
                .joined(separator: " ")
            if let date = try? Date(normalized, strategy: strategy) {
                result[pid] = date
            }
        }
        return result
    }

    // MARK: - Git Resolution

    private func resolveProjects(
        parsed: [ParsedPort],
        cwds: [Int32: String],
        startTimes: [Int32: Date],
        containers: [UInt16: ContainerInfo]
    ) async -> [ActivePort] {
        var gitRoots: [String: URL] = [:]
        var branches: [String: String] = [:]

        for (_, cwd) in cwds {
            guard gitRoots[cwd] == nil else { continue }

            let root: URL?
            if let cached = Self.cache.gitRoot(for: cwd) {
                root = cached
            } else {
                root = Self.findGitRoot(from: cwd)
                Self.cache.setGitRoot(root, for: cwd)
            }

            if let root {
                gitRoots[cwd] = root
                let rootPath = root.path()
                if branches[rootPath] == nil {
                    if let cached = Self.cache.branch(for: rootPath, ttl: Self.branchTTL) {
                        branches[rootPath] = cached
                    } else {
                        let branch = await resolveGitBranch(at: rootPath)
                        branches[rootPath] = branch
                        Self.cache.setBranch(branch, for: rootPath)
                    }
                }
            }
        }

        let activeCWDs = Set(cwds.values)
        let activeRootPaths = Set(gitRoots.values.map { $0.path() })
        Self.cache.prune(activeCWDs: activeCWDs, activeRootPaths: activeRootPaths)

        return parsed.compactMap { info -> ActivePort? in
            let cwd = cwds[info.pid]
            let gitRoot = cwd.flatMap { gitRoots[$0] }
            let rootPath = gitRoot?.path()
            let isContainerRuntime = Self.containerRuntimeName(for: info.processName) != nil
            let container = containers[info.port]

            if gitRoot == nil, container == nil, !isContainerRuntime,
               !Self.shouldKeepFallbackProcess(processName: info.processName, cwd: cwd) {
                if Log.isVerbose {
                    Log.scanner.debug("Skipping non-project process '\(info.processName)' on port \(info.port)")
                }
                return nil
            }

            let projectName: String
            let branch: String
            if let container {
                // Container runtime port matched to a running container: prefer the
                // compose project/service over the generic runtime label.
                projectName = container.project
                branch = container.service
            } else {
                projectName = Self.displayName(
                    processName: info.processName,
                    cwd: cwd,
                    gitRoot: gitRoot
                )
                branch = rootPath.flatMap { branches[$0] } ?? ""
            }

            if gitRoot == nil, container == nil, Log.isVerbose {
                Log.scanner.debug("Using fallback label '\(projectName)' for PID \(info.pid) on port \(info.port)")
            }

            return ActivePort(
                port: info.port,
                pid: info.pid,
                projectName: projectName,
                branch: branch,
                startTime: startTimes[info.pid],
                isContainer: container != nil || isContainerRuntime
            )
        }
    }

    static func displayName(processName: String, cwd: String?, gitRoot: URL?) -> String {
        if let gitRoot {
            return gitRoot.lastPathComponent
        }

        if let runtime = containerRuntimeName(for: processName) {
            return runtime
        }

        if let cwd {
            let basename = URL(filePath: cwd).lastPathComponent
            if isMeaningfulDirectoryName(basename) {
                return basename
            }
        }

        return processName
    }

    static func shouldKeepFallbackProcess(processName: String, cwd: String?) -> Bool {
        let normalized = processName.lowercased()
        if allowedFallbackProcessNames.contains(normalized) {
            return true
        }

        if containerRuntimeName(for: normalized) != nil {
            return true
        }

        if normalized.hasPrefix("python"),
           normalized.dropFirst("python".count).allSatisfy({ $0.isNumber || $0 == "." }) {
            return true
        }

        if let cwd {
            let basename = URL(filePath: cwd).lastPathComponent
            if isMeaningfulDirectoryName(basename),
               allowedFallbackProcessNames.contains(basename.lowercased()) {
                return true
            }
        }

        return false
    }

    static func isLikelyContainerForwarder(processName: String) -> Bool {
        let normalized = processName.lowercased()
        return normalized.hasPrefix("code")
            || normalized.hasPrefix("cursor")
            || normalized.hasPrefix("codium")
            || normalized.hasPrefix("windsurf")
    }

    // Returns the display label for a container runtime if `name` is one, else nil.
    // lsof truncates COMMAND to 9 chars by default, so
    // "com.docker.backend" → "com.docke", "docker-proxy" → "docker-pr".
    // OrbStack ("OrbStack", 8 chars) is not truncated.
    static func containerRuntimeName(for name: String) -> String? {
        let lower = name.lowercased()
        if lower.contains("orbstack") {
            return "OrbStack"
        }
        if lower.contains("docker") || lower.hasPrefix("com.dock") || lower.hasPrefix("vpnkit") {
            return "Docker"
        }
        return nil
    }

    static func isMeaningfulDirectoryName(_ name: String) -> Bool {
        guard !name.isEmpty, name != "/", !name.hasPrefix(".") else { return false }
        let ignored = Set(["_build", "build", "tmp", "dist", "deps"])
        return !ignored.contains(name)
    }

    private func resolveGitBranch(at gitRoot: String) async -> String {
        guard let output = try? await runShell(
            "/usr/bin/git", args: ["-C", gitRoot, "rev-parse", "--abbrev-ref", "HEAD"],
            timeout: 5
        ) else { return "" }
        return output.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func findGitRoot(from path: String) -> URL? {
        var current = URL(filePath: path)
        let fm = FileManager.default
        while current.path() != "/" {
            if fm.fileExists(atPath: current.appending(path: ".git").path()) {
                return current
            }
            current = current.deletingLastPathComponent()
        }
        return nil
    }

    // MARK: - Shell Execution (async, with timeout)

    private func runShell(
        _ executable: String,
        args: [String],
        timeout: TimeInterval,
        environment: [String: String]? = nil
    ) async throws -> String {
        let command = ([executable] + args).joined(separator: " ")
        let token = UUID()

        // Run the blocking process on a background thread via a detached task,
        // then race it against a timeout task using withTaskGroup.
        return try await withThrowingTaskGroup(of: String.self) { group in
            group.addTask {
                try await Self.runProcess(
                    executable: executable,
                    args: args,
                    environment: environment,
                    token: token
                )
            }

            group.addTask {
                try await Task.sleep(for: .seconds(timeout))
                Self.processTracker.terminate(token: token)
                Log.shell.warning("Process timed out: \(command)")
                throw ScanError.lsofTimeout
            }

            // Return the first result (success or error); cancel the other task.
            defer {
                Self.processTracker.terminate(token: token)
                group.cancelAll()
            }
            let result = try await group.next()!
            return result
        }
    }

    private static func runProcess(
        executable: String,
        args: [String],
        environment: [String: String]?,
        token: UUID
    ) async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            let process = Process()
            let stdout = Pipe()
            let stderr = Pipe()

            process.executableURL = URL(filePath: executable)
            process.arguments = args
            process.standardOutput = stdout
            process.standardError = stderr

            if let env = environment {
                var combined = ProcessInfo.processInfo.environment
                for (k, v) in env { combined[k] = v }
                process.environment = combined
            }

            do {
                processTracker.store(process, for: token)
                try process.run()
                let data = stdout.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                processTracker.clear(token: token)

                if process.terminationStatus != 0 {
                    let errData = stderr.fileHandleForReading.availableData
                    let errMsg = String(data: errData, encoding: .utf8) ?? ""
                    if Log.isVerbose {
                        Log.shell.debug("Process exit \(process.terminationStatus): \(executable) — \(errMsg)")
                    }
                    continuation.resume(throwing: ScanError.lsofFailed(
                        "\(executable) exited with \(process.terminationStatus)"))
                    return
                }

                let output = String(data: data, encoding: .utf8) ?? ""
                continuation.resume(returning: output)
            } catch {
                processTracker.clear(token: token)
                continuation.resume(throwing: ScanError.lsofFailed(error.localizedDescription))
            }
        }
    }
}

// MARK: - Cache

final class CacheStore: Sendable {
    private let _gitRoots = OSAllocatedUnfairLock(initialState: [String: URL?]())
    private let _branches = OSAllocatedUnfairLock(initialState: [String: (branch: String, resolved: Date)]())

    func gitRoot(for cwd: String) -> URL?? {
        _gitRoots.withLock { $0[cwd] }
    }

    func setGitRoot(_ root: URL?, for cwd: String) {
        _gitRoots.withLock { $0[cwd] = root }
    }

    func branch(for rootPath: String, ttl: TimeInterval) -> String? {
        _branches.withLock { cache in
            guard let entry = cache[rootPath],
                  Date().timeIntervalSince(entry.resolved) < ttl else { return nil }
            return entry.branch
        }
    }

    func setBranch(_ branch: String, for rootPath: String) {
        _branches.withLock { $0[rootPath] = (branch, Date()) }
    }

    func prune(activeCWDs: Set<String>, activeRootPaths: Set<String>) {
        _gitRoots.withLock { cache in
            cache = cache.filter { activeCWDs.contains($0.key) }
        }
        _branches.withLock { cache in
            cache = cache.filter { activeRootPaths.contains($0.key) }
        }
    }
}

final class ProcessTracker: @unchecked Sendable {
    private let lock = NSLock()
    private var processes: [UUID: Process] = [:]

    func store(_ process: Process, for token: UUID) {
        lock.lock()
        processes[token] = process
        lock.unlock()
    }

    func clear(token: UUID) {
        lock.lock()
        processes[token] = nil
        lock.unlock()
    }

    func terminate(token: UUID) {
        lock.lock()
        let process = processes[token]
        lock.unlock()

        guard let process, process.isRunning else { return }
        process.terminate()
    }
}

// MARK: - Fake Scanner (for tests & previews)

struct FakePortScanner: PortScanning {
    var ports: [ActivePort]
    var delay: TimeInterval
    var shouldFail: Bool

    init(
        ports: [ActivePort] = FakePortScanner.samplePorts,
        delay: TimeInterval = 0.1,
        shouldFail: Bool = false
    ) {
        self.ports = ports
        self.delay = delay
        self.shouldFail = shouldFail
    }

    func scan() async -> ScanResult {
        try? await Task.sleep(for: .seconds(delay))
        if shouldFail {
            return .failure(.lsofFailed("Simulated failure"), ports)
        }
        let diag = ScanDiagnostics(
            duration: delay,
            portsFound: ports.count,
            dataSource: "fake",
            timestamp: Date()
        )
        return .success(ports, diag)
    }

    static let samplePorts: [ActivePort] = [
        ActivePort(port: 3000, pid: 1001, projectName: "my-frontend",
                   branch: "main", startTime: Date().addingTimeInterval(-3600)),
        ActivePort(port: 5173, pid: 1002, projectName: "vite-app",
                   branch: "feature/dark-mode", startTime: Date().addingTimeInterval(-600)),
        ActivePort(port: 8080, pid: 1003, projectName: "api-server",
                   branch: "develop", startTime: Date().addingTimeInterval(-86400)),
    ]
}
