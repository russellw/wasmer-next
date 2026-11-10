// SDK-neutral async bootstrap. The SDK owns public wrappers and worker asset URLs.
// An optional caller-realm host supplies a synchronous Worker-shaped factory
// and absolute URL base. Neither host functions nor browser globals are cloned.
export async function startCoordinator(options, onMessage = () => {}, host) {
    if (host === undefined && (!globalThis.isSecureContext || !globalThis.crossOriginIsolated || typeof SharedArrayBuffer !== "function")) {
        throw new Error("WASIX browser runtime requires a secure, cross-origin isolated SharedArrayBuffer context");
    }
    if (host !== undefined && (!host || typeof host.createWorker !== "function")) {
        throw new TypeError("expected a runtime host Worker factory and absolute baseURL");
    }
    if (typeof SharedArrayBuffer !== "function" || !(options.module instanceof WebAssembly.Module) ||
        !(options.memory instanceof WebAssembly.Memory) ||
        !(options.memory.buffer instanceof SharedArrayBuffer)) {
        throw new Error("expected a compiled runtime module and its shared runtime memory");
    }
    // Cancellation belongs to the caller realm and must never be cloned into workers.
    const { signal, ...workerOptions } = options;
    signal?.throwIfAborted();
    const config = {
        taskLimit: 64, serviceLimit: 4, prewarm: 2, servicePrewarm: 2,
        stackSize: 1024 * 1024, admissionTimeout: 10000, ...workerOptions,
    };
    for (const role of ["task", "service"]) {
        const limit = config[role + "Limit"];
        const prewarm = config[role === "task" ? "prewarm" : "servicePrewarm"];
        if (!Number.isSafeInteger(limit) || limit < 0 || limit > 1024 ||
            !Number.isSafeInteger(prewarm) || prewarm < 0 || prewarm > limit) {
            throw new Error("invalid bounded worker capacity for " + role);
        }
    }
    if (!Number.isSafeInteger(config.stackSize) || config.stackSize < 65536 || config.stackSize % 65536 !== 0 ||
        !Number.isFinite(config.admissionTimeout) || config.admissionTimeout <= 0 || config.admissionTimeout > 60000) {
        throw new Error("invalid worker stack size or admission deadline");
    }
    const baseURL = host === undefined ? globalThis.location.href : new URL(host.baseURL).href;
    if (config.memoryCopyUrl) {
        config.memoryCopyUrl = new URL(config.memoryCopyUrl, baseURL).href;
        config.memoryClientUrl = new URL(config.memoryClientUrl ?? "./client.js", config.memoryCopyUrl).href;
        config.memoryCopyTimeout ??= config.admissionTimeout;
        if (!Number.isFinite(config.memoryCopyTimeout) || config.memoryCopyTimeout <= 0 || config.memoryCopyTimeout > 60000)
            throw new Error("invalid memory-copy deadline");
    }
    if (config.ioModuleUrl) config.ioModuleUrl = new URL(config.ioModuleUrl, baseURL).href;
    config.bindingsUrl = new URL(config.bindingsUrl, baseURL).href;
    config.workerUrl = new URL(config.workerUrl ?? "./worker.js", import.meta.url).href;
    const coordinatorURL = new URL(config.coordinatorUrl ?? "./coordinator.js", import.meta.url);
    const coordinator = host === undefined
        ? new Worker(coordinatorURL, { type: "module" })
        : host.createWorker(coordinatorURL, { type: "module" });
    const nativeExit = coordinator.exited;
    async function retire() {
        let failure;
        try { await coordinator.terminate(); } catch (error) { failure = { error }; }
        // A rejected terminate request does not release an independently
        // captured native owner. DOM workers expose no such completion.
        try { await nativeExit; } catch (error) { failure ??= { error }; }
        if (failure) throw failure.error;
    }
    // Routing only: no Store, Instance, callback or guest graph is registered here.
    const coordinators = globalThis[Symbol.for("wasixv2.browser.coordinators")] ??= new WeakMap();
    if (coordinators.has(config.memory)) {
        // A supplied host may expose actual native retirement. Keep that
        // ownership even when this heap cannot publish a second coordinator.
        try { await retire(); } catch {}
        throw new Error("runtime memory already has a coordinator");
    }
    coordinators.set(config.memory, coordinator);
    let timer;
    let abort;
    let abortRequested = false;
    let ready = false;
    let disposed = false;
    let disposal;
    function dispose() {
        if (disposed) return disposal;
        let resolve, reject;
        disposal = new Promise((done, fail) => { resolve = done; reject = fail; });
        disposed = true;
        // A tombstone permits a racing stale Waker to observe closed ownership
        // without retaining the coordinator or allowing a poisoned heap to reboot.
        coordinators.set(config.memory, null);
        clearTimeout(timer);
        if (abort) signal?.removeEventListener("abort", abort);
        coordinator.onmessage = coordinator.onerror = coordinator.onmessageerror = null;
        // DOM termination remains request-only. A native host can return its
        // real exit promise; bootstrap failure must retain that completion.
        retire().then(resolve, reject);
        // Terminal event delivery is synchronous. Its owner can join the same
        // native completion later without an unhandled cleanup rejection here.
        disposal.catch(() => {});
        return disposal;
    }
    try {
        await new Promise((resolve, reject) => {
            const notifyFailure = (data, origin, originalError) => {
                // Only this caller-local argument can contain an owned Promise
                // or Error. Keep the ordinary message cloneable and unchanged.
                let message = data;
                if (Object.hasOwn(data, "nativeWorkerFailure")) {
                    const { nativeWorkerFailure: _nativeWorkerFailure, ...rest } = data;
                    message = rest;
                }
                const terminal = { retirement: disposal, ...(origin ? { origin } : {}),
                    ...(originalError ? { originalError } : {}) };
                if (host === undefined) { onMessage(message, terminal); return; }
                // The failure was already selected before this notification.
                // A secondary native-host callback must not escape its event
                // emitter or replace the primary error while retirement joins.
                try { onMessage(message, terminal); } catch {}
            };
            timer = setTimeout(() => reject(new Error("coordinator bootstrap timed out")), config.admissionTimeout);
            coordinator.onerror = (event) => {
                if (disposed) return;
                const originalError = event.error instanceof Error ? event.error : new Error(event.message);
                dispose();
                reject(originalError);
                notifyFailure({ type: "fatal", error: event.message }, "native-worker", originalError);
            };
            coordinator.onmessage = ({ data }) => {
                if (disposed || (abortRequested && data.type === "ready")) return;
                if (host !== undefined && data.type === "ready") {
                    // Native host callbacks can synchronously fail or reenter
                    // cancellation. Do not publish a healthy owner first.
                    try { onMessage(data, { retire: dispose }); }
                    catch (error) { dispose(); reject(error); return; }
                    if (disposed) reject(new Error("coordinator disposed during bootstrap"));
                    else if (!abortRequested) { ready = true; clearTimeout(timer); resolve(); }
                    return;
                }
                if (data.type === "fatal" || data.type === "stopped") dispose();
                if (data.type === "ready") { ready = true; clearTimeout(timer); resolve(); }
                if (data.type === "fatal") { clearTimeout(timer); reject(abortRequested && data.ownerAbort === true ? signal.reason : new Error(data.error)); }
                if (data.type === "stopped") reject(new Error("coordinator stopped during bootstrap"));
                if (data.type === "fatal" || (data.type === "stopped" && !ready)) {
                    notifyFailure(data, data.type === "fatal" && data.nativeWorkerFailure === true ? "native-worker" : undefined);
                }
                else if (data.type === "ready") onMessage(data, { retire: dispose });
                else onMessage(data);
            };
            coordinator.onmessageerror = () => {
                if (disposed) return;
                dispose();
                reject(new Error("coordinator message could not be decoded"));
                notifyFailure({ type: "fatal", error: "coordinator message could not be decoded" });
            };
            if (nativeExit) {
                // Native self-close is not a B2 terminal acknowledgement. This
                // observer remains live after readiness until protocol disposal.
                const failed = (error, nativeWorkerFailure = false) => {
                    if (disposed) return;
                    dispose();
                    reject(error);
                    notifyFailure({ type: "fatal", error: error.message },
                        nativeWorkerFailure ? "native-worker" : undefined, nativeWorkerFailure ? error : undefined);
                };
                Promise.resolve(nativeExit).then(
                    code => failed(new Error(`coordinator exited before protocol shutdown with status ${code}`), true),
                    cause => failed(cause instanceof Error ? cause : new Error(String(cause))),
                // Native exit was already the first failure. A secondary
                // notification callback cannot replace its original cause.
                ).catch(() => {});
            }
            abort = () => {
                if (disposed || abortRequested) return;
                abortRequested = true;
                try {
                    // Wait for the existing whole-heap discard notification rather
                    // than terminating only the coordinator and losing child custody.
                    coordinator.postMessage({ type: "abort", error: "runtime aborted by its owner" });
                } catch (error) {
                    dispose();
                    reject(error);
                    notifyFailure({ type: "fatal", error: String(error) });
                }
            };
            signal?.addEventListener("abort", abort, { once: true });
            if (signal?.aborted) abort();
            else coordinator.postMessage({ ...config, type: "init" });
        });
        return coordinator;
    } catch (error) {
        try { await dispose(); } catch {}
        throw error;
    } finally { clearTimeout(timer); }
}
