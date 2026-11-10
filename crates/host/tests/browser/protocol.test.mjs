// Coordinator regressions without a browser. Real workers/TLS/SAB execute in run.mjs.
import { readFile } from "node:fs/promises";
import vm from "node:vm";
import test from "node:test";
import assert from "node:assert/strict";
import { Worker as NativeWorker } from "node:worker_threads";

const source = await readFile(new URL("../../src/browser/coordinator.js", import.meta.url), "utf8");
const flush = () => new Promise((resolve) => setImmediate(resolve));

async function setup(extra = {}) {
    const output = [];
    const instances = [];
    const control = { fail: false, hold: false, reject: false };
    class Worker {
        constructor() {
            if (control.fail) throw new Error("worker creation failed");
            this.messages = [];
            instances.push(this);
        }
        postMessage(data) {
            this.messages.push(data);
            if (data.type === "boot" && !control.holdBoot) queueMicrotask(() => this.onmessage({ data: { type: "booted" } }));
            if (data.type === "prepare" && !control.hold) {
                queueMicrotask(() => this.onmessage({ data: { type: control.reject ? "rejected" : "prepared", id: data.id } }));
            }
            if (data.type === "retire" && this.messages[0].type === "boot" && !control.holdRetire) queueMicrotask(() => this.onmessage({ data: { type: "retired" } }));
        }
        terminate() { this.terminated = true; }
        send(data) { this.onmessage({ data }); }
    }
    class MessageChannel {
        constructor() {
            this.port1 = { close() { this.closed = true; } };
            this.port2 = { close() { this.closed = true; } };
        }
    }
    const context = vm.createContext({ Worker, MessageChannel, Atomics, setTimeout, clearTimeout, postMessage: (data) => output.push(data), close: () => { control.closed = true; } });
    vm.runInContext(source, context);
    await context.onmessage({ data: {
        type: "init", workerUrl: "worker.js", taskLimit: 1, serviceLimit: 1,
        prewarm: 0, servicePrewarm: 0, admissionTimeout: 1000,
        memory: { buffer: new SharedArrayBuffer(64) }, ...extra,
    } });
    assert.equal(output[0].type, "ready");
    function prepare(id, service = false) {
        const reply = new Int32Array(new SharedArrayBuffer(4));
        instances[0].send({ type: "prepare", id, service, reply });
        return reply;
    }
    return { output, instances, control, context, prepare };
}

async function busyTask() {
    const h = await setup();
    h.prepare(1);
    await flush();
    h.instances[0].send({ type: "commit", id: 1 });
    h.task = h.instances[2];
    h.words = new Int32Array(vm.runInContext("options.memory.buffer", h.context));
    return h;
}

test("JSPI admissions select only the task Promise driver", async () => {
    const h = await setup();
    const reply = new Int32Array(new SharedArrayBuffer(4));
    h.instances[0].send({ type: "prepare", id: 1, jspi: true, reply });
    await flush();
    assert.equal(h.instances[2].messages.at(-1).jspi, true);
    h.instances[0].send({ type: "commit", id: 1 });
    assert.equal(h.instances[2].messages.at(-1).jspi, true);
    const service = new Int32Array(new SharedArrayBuffer(4));
    h.instances[0].send({ type: "prepare", id: 2, jspi: true, service: true, reply: service });
    assert.equal(Atomics.load(service, 0), 2);
});

for (const ordering of ["before-registration", "after-registration"]) {
    test(`async wake ${ordering} reaches every owner ticket without waitAsync`, async () => {
        const h = await busyTask();
        if (ordering === "before-registration") {
            Atomics.add(h.words, 0, 1);
            h.instances[1].send({ type: "wake-word", address: 0 });
        }
        for (const ticket of [1, 2]) h.task.send({ type: "watch-word", ticket, address: 0, observed: 0 });
        if (ordering === "after-registration") {
            assert.equal(vm.runInContext("wordWaiters.get(0).size", h.context), 2);
            Atomics.add(h.words, 0, 1);
            h.instances[1].send({ type: "wake-word", address: 0 });
        }
        assert.deepEqual(h.task.messages.filter(data => data.type === "wake-word").map(data => data.ticket), [1, 2]);
        assert.equal(vm.runInContext("wordWaiters.size", h.context), 0);
        h.task.send({ type: "idle", id: 1 });
        assert(!h.output.some(data => data.type === "fatal"));
    });
}

test("canceling one async ticket preserves siblings and stale wakes cannot consume a new wait", async () => {
    const h = await busyTask();
    h.task.send({ type: "watch-word", ticket: 1, address: 0, observed: 0 });
    h.task.send({ type: "watch-word", ticket: 2, address: 0, observed: 0 });
    h.task.send({ type: "unwatch-word", ticket: 1 });
    Atomics.add(h.words, 0, 1);
    await h.context.onmessage({ data: { type: "wake-word", address: 0 } });
    assert.deepEqual(h.task.messages.filter(data => data.type === "wake-word").map(data => data.ticket), [2]);
    h.task.send({ type: "watch-word", ticket: 3, address: 0, observed: 1 });
    h.task.send({ type: "unwatch-word", ticket: 1 });
    h.instances[1].send({ type: "wake-word", address: 0 });
    assert.equal(vm.runInContext("wordWaiters.get(0).size", h.context), 1);
    h.task.send({ type: "unwatch-word", ticket: 3 });
    h.task.send({ type: "idle", id: 1 });
    await h.context.onmessage({ data: { type: "shutdown" } });
    await flush();
    assert.equal(vm.runInContext("wordWaiters.size", h.context), 0);
    assert.equal(h.output.at(-1).type, "stopped");
});

for (const invalid of [{ address: 1 }, { address: 64 }, { address: -4 }, { ticket: 0 }, { observed: 0.5 }]) {
    test(`async wait rejects invalid runtime ownership data ${JSON.stringify(invalid)}`, async () => {
        const h = await busyTask();
        h.task.send({ type: "watch-word", ticket: 1, address: 0, observed: 0, ...invalid });
        assert.equal(h.output.at(-1).type, "fatal");
        assert(h.instances.every(worker => worker.terminated));
        assert.equal(vm.runInContext("wordWaiters.size", h.context), 0);
    });
}

test("worker failure clears every pending word registration", async () => {
    const h = await busyTask();
    h.task.send({ type: "watch-word", ticket: 1, address: 0, observed: 0 });
    h.task.send({ type: "watch-word", ticket: 2, address: 4, observed: 0 });
    h.task.send({ type: "fatal", error: "task died while waiting" });
    assert.equal(vm.runInContext("wordWaiters.size", h.context), 0);
    assert.equal(vm.runInContext("workers.size", h.context), 0);
});

test("idle publication refuses pending async registrations", async () => {
    const h = await busyTask();
    h.task.send({ type: "watch-word", ticket: 1, address: 0, observed: 0 });
    h.task.send({ type: "idle", id: 1 });
    assert.equal(h.output.at(-1).type, "fatal");
    assert.match(h.output.at(-1).error, /live async waits/);
});

test("raw word notifications route only asynchronous runtime words and distinguish closed ownership", async () => {
    const { notifyWord } = await import("../../src/browser/bridge.js");
    const key = Symbol.for("wasixv2.browser.coordinators");
    const saved = globalThis[key];
    const memory = new WebAssembly.Memory({ initial: 1, maximum: 1, shared: true });
    const messages = [];
    try {
        globalThis[key] = new WeakMap([[memory, { postMessage: data => messages.push(data) }]]);
        notifyWord(memory, 0, false);
        assert.equal(messages.length, 0);
        notifyWord(memory, 0, true);
        assert.deepEqual(messages, [{ type: "wake-word", address: 0 }]);
        globalThis[key].set(memory, null);
        notifyWord(memory, 0, true);
        assert.equal(messages.length, 1, "closed runtime ignores a racing stale wake");
        globalThis[key].delete(memory);
        assert.throws(() => notifyWord(memory, 0, true), /no owning runtime coordinator/);
    } finally {
        if (saved === undefined) delete globalThis[key];
        else globalThis[key] = saved;
    }
});

test("owner Promise steps retain one exact invocation and settle errors without changing identity", async () => {
    const { drivePromise } = await import("../../src/browser/bridge.js");
    const saved = { worker: globalThis.__wasixWorker, post: globalThis.postMessage };
    const waits = [];
    const events = [];
    const fatal = [];
    try {
        globalThis.postMessage = data => fatal.push(data);
        globalThis.__wasixWorker = {
            watchWord(address, observed) {
                assert.equal(address, 12);
                assert.equal(observed, 7);
                const ticket = waits.length + 1;
                let resolve;
                const promise = new Promise(done => { resolve = done; });
                waits.push({ resolve });
                return { ticket, promise };
            },
            cancelWordWait(ticket) { events.push(`cancel:${ticket}`); },
        };
        const value = { exact: "original result" };
        const promise = drivePromise(() => {
            events.push("first");
            return [2, 12, 7, () => { events.push("second"); return [0, value]; }];
        });
        assert.deepEqual(events, [], "first poll must be a later owner microtask");
        await Promise.resolve();
        assert.deepEqual(events, ["first"]);
        waits[0].resolve();
        assert.equal(await promise, value);
        assert.deepEqual(events, ["first", "cancel:1", "second"]);
        const original = { hostAbort: Symbol("same error") };
        await assert.rejects(drivePromise(() => [1, original]), error => error === original);
        assert.equal(fatal.length, 0, "ordinary future errors must not poison the heap");
        await assert.rejects(drivePromise(() => { throw new Error("poll protocol failed"); }), /protocol failed/);
        assert.equal(fatal.length, 1);
        assert.equal(fatal[0].type, "fatal");
    } finally {
        if (saved.worker === undefined) delete globalThis.__wasixWorker;
        else globalThis.__wasixWorker = saved.worker;
        if (saved.post === undefined) delete globalThis.postMessage;
        else globalThis.postMessage = saved.post;
    }
});

test("worker constructor failure rejects admission without acceptance", async () => {
    const h = await setup();
    h.control.fail = true;
    const reply = h.prepare(1);
    await flush();
    assert.equal(Atomics.load(reply, 0), 2);
    assert.equal(vm.runInContext("admissions.size", h.context), 0);
    assert(!h.output.some(({ type }) => type === "fatal"));
});

test("dispatch cloning releases coordinator envelope roots before ownership commit", async () => {
    const h = await setup({ prewarm: 1 });
    h.control.hold = true;
    const envelope = { memory: "opaque engine object" };
    const data = { type: "prepare", id: 1, reply: new Int32Array(new SharedArrayBuffer(4)), envelope };
    h.instances[0].send(data);
    await flush();
    assert.equal(data.envelope, null, "incoming event must not retain a second envelope root");
    assert.equal(vm.runInContext("admissions.get(1).envelope", h.context), null);
    assert.equal(h.instances[2].messages.at(-1).envelope, envelope, "receiver gets the original opaque value");
    h.instances[2].send({ type: "fatal", error: "test finished" });
});

test("full guest capacity fails promptly while reserved service capacity progresses", async () => {
    const h = await setup();
    const first = h.prepare(1);
    await flush();
    assert.equal(Atomics.load(first, 0), 1);
    h.instances[0].send({ type: "commit", id: 1 });
    assert.equal(h.instances[2].messages.at(-1).type, "run");
    const full = h.prepare(2);
    const service = h.prepare(3, true);
    await flush();
    assert.equal(Atomics.load(full, 0), 2);
    assert.equal(Atomics.load(service, 0), 1);
    h.instances[0].send({ type: "commit", id: 3 });
    assert.equal(h.instances[3].messages.at(-1).type, "run");
});

test("embedder events retain service ownership until its subsequent idle publication", async () => {
    const h = await setup();
    h.prepare(1, true);
    await flush();
    h.instances[0].send({ type: "commit", id: 1 });
    const service = h.instances[2];
    const state = vm.runInContext("[...workers.values()].find(state => state.role === 'service')", h.context);
    const value = { generation: 7, token: 12, kind: "finished" };
    service.send({ type: "event", worker: -1, value });
    assert.equal(h.output.at(-1).type, "event");
    assert.equal(h.output.at(-1).worker, state.id, "identity comes from the coordinator");
    assert.equal(h.output.at(-1).value, value);
    assert.equal(state.status, "busy");
    assert.equal(Atomics.load(h.prepare(2, true), 0), 2, "event does not free service capacity");
    service.send({ type: "idle", id: 1 });
    assert.equal(h.output.at(-1).type, "idle");
    assert.equal(h.output.at(-1).worker, state.id);
    const reply = h.prepare(3, true);
    await flush();
    assert.equal(Atomics.load(reply, 0), 1);
});

test("cancellation wins a delayed ready reply and retires the unclaimed worker", async () => {
    const h = await setup();
    h.control.hold = true;
    const reply = h.prepare(1);
    await flush();
    Atomics.compareExchange(reply, 0, 0, 3);
    h.instances[0].send({ type: "cancel", id: 1 });
    h.instances[2].send({ type: "prepared", id: 1 });
    await flush();
    assert.equal(Atomics.load(reply, 0), 3);
    assert.equal(vm.runInContext("admissions.size", h.context), 0);
    assert(h.instances[2].terminated);
    assert(!h.instances[2].messages.some(({ type }) => type === "run"));
});

test("object-envelope rejection cannot dispatch its closure", async () => {
    const h = await setup();
    h.control.reject = true;
    const reply = h.prepare(1);
    await flush();
    assert.equal(Atomics.load(reply, 0), 2);
    assert(h.instances[2].terminated);
    assert(!h.instances[2].messages.some(({ type }) => type === "run"));
});

test("accepted worker failure poisons the heap and terminates every worker", async () => {
    const h = await setup();
    h.prepare(1);
    await flush();
    h.instances[0].send({ type: "commit", id: 1 });
    h.instances[2].send({ type: "fatal", error: "accepted trap" });
    assert(h.instances.every(({ terminated }) => terminated));
    assert.equal(h.output.at(-1).type, "fatal");
    assert.equal(vm.runInContext("poisoned", h.context), true);
    assert(h.control.closed);
    assert.equal(vm.runInContext("options", h.context), null);
});

test("bootstrap rejects missing isolation, nonshared heaps and invalid capacity before worker creation", async () => {
    const { startCoordinator } = await import("../../src/browser/bootstrap.js");
    const saved = { isSecureContext: globalThis.isSecureContext, crossOriginIsolated: globalThis.crossOriginIsolated, WebAssembly: globalThis.WebAssembly };
    try {
        await assert.rejects(startCoordinator({}), /secure/);
        globalThis.isSecureContext = true;
        globalThis.crossOriginIsolated = true;
        class Module {}
        class Memory { constructor(buffer) { this.buffer = buffer; } }
        globalThis.WebAssembly = { Module, Memory };
        await assert.rejects(startCoordinator({ module: new Module(), memory: new Memory(new ArrayBuffer(4)) }), /shared runtime memory/);
        const options = { module: new Module(), memory: new Memory(new SharedArrayBuffer(4)), taskLimit: -1 };
        await assert.rejects(startCoordinator(options), /capacity/);
        await assert.rejects(startCoordinator({ ...options, taskLimit: 4, stackSize: 1 }), /stack size/);
    } finally { Object.assign(globalThis, saved); }
});


test("normal shutdown releases the runtime options and closes its coordinator", async () => {
    const h = await setup({ prewarm: 1, servicePrewarm: 1 });
    await h.context.onmessage({ data: { type: "shutdown" } });
    await flush();
    assert(h.instances.every(({ terminated }) => terminated));
    assert(h.control.closed);
    assert.equal(h.output.at(-1).type, "stopped");
    assert.equal(vm.runInContext("options", h.context), null);
});

test("copy worker is coordinator-created pure JS and terminated with normal/fatal runtime", async () => {
    // Host transports ports without importing an engine or entering runtime Rust.
    // setup's vm context receives MessageChannel from its injected globals below.
    const h = await setup({ memoryCopyUrl: "copy-worker.js", memory: "runtime-heap" });
    assert.equal(h.instances.length, 3);
    const service = h.instances[0], root = h.instances[1];
    assert.deepEqual(service.messages.map(({ type }) => type), ["init", "connect", "connect"]);
    assert.equal(service.messages[0].memory, "runtime-heap");
    assert(!service.messages.some(({ type }) => type === "boot"));
    assert(root.messages[0].memoryCopyPort);
    await h.context.onmessage({ data: { type: "shutdown" } });
    await flush();
    assert.equal(service.messages.at(-1).type, "retire");
    assert(!service.terminated, "normal pure-JS retirement must run on its event loop");
    assert(root.terminated);
    assert(!h.output.some(data => data.type === "stopped"), "parent retains copy owner until cleanup ACK");
    service.send({ type: "retired" });
    assert(service.terminated);
    assert.equal(h.output.at(-1).type, "stopped");

    const failed = await setup({ memoryCopyUrl: "copy-worker.js" });
    failed.instances[0].onerror({ preventDefault() {}, message: "copy service died" });
    assert(failed.instances.every(({ terminated }) => terminated));
    assert.equal(failed.output.at(-1).type, "fatal");
    assert.equal(vm.runInContext("memoryCopies", failed.context), null);
});

test("retired child detaches handlers and captured late callbacks cannot poison its owner", async () => {
    const h = await setup();
    const child = h.instances[1];
    const stale = { message: child.onmessage, error: child.onerror, decode: child.onmessageerror };
    await h.context.onmessage({ data: { type: "shutdown" } });
    await flush();
    assert(child.terminated);
    assert.equal(child.onmessage, null);
    assert.equal(child.onerror, null);
    assert.equal(child.onmessageerror, null);
    const count = h.output.length;
    stale.message({ data: { type: "fatal", error: "late retired child" } });
    stale.error({ preventDefault() {}, message: "late retired child" });
    stale.decode();
    assert.equal(h.output.length, count);
    assert.equal(h.output.at(-1).type, "stopped");
});


test("timer rearm is routed to independent event worker while a task is busy", async () => {
    const h = await setup();
    const timer = h.instances[1];
    assert.equal(timer.messages[0].role, "timer");
    h.prepare(1);
    await flush();
    h.instances[0].send({ type: "commit", id: 1 });
    h.instances[2].send({ type: "timer-rearm" });
    assert.equal(timer.messages.at(-1).type, "timer-rearm");
    assert.equal(h.instances[2].messages.at(-1).type, "run");
    timer.send({ type: "fatal", error: "timer worker died" });
    assert(h.instances.every(({ terminated }) => terminated));
    assert.equal(h.output.at(-1).type, "fatal");
});

test("stale timer callbacks cannot resurrect a canceled or rearmed alarm", async () => {
    const { timerDriver } = await import("../../src/browser/timer-driver.js");
    const callbacks = [];
    const cleared = [];
    let ticks = 0;
    let delay = 10;
    const driver = timerDriver({
        browser_timers_tick() { ticks++; return delay; },
        browser_timers_pending() { return 0; },
    }, (callback, ms) => { assert.equal(ms, delay); callbacks.push(callback); return callbacks.length; },
    (id) => cleared.push(id));
    driver.rearm();
    driver.rearm();
    assert.deepEqual(cleared, [1]);
    callbacks[0]();
    assert.equal(ticks, 2, "queued stale callback must not touch Rust");
    callbacks[1]();
    assert.equal(ticks, 3);
    delay = -1;
    driver.rearm();
    assert.deepEqual(cleared, [1, 3]);
    callbacks[2]();
    assert.equal(ticks, 4);
    driver.close();
    assert.equal(callbacks.length, 3);
});

test("timer retirement refuses live waits instead of abandoning them", async () => {
    const { timerDriver } = await import("../../src/browser/timer-driver.js");
    const driver = timerDriver({ browser_timers_tick() { return -1; }, browser_timers_pending() { return 1; } });
    assert.throws(() => driver.close(), /live waits/);
});

test("timer worker startup failure is fatal before runtime readiness", async () => {
    const output = [];
    const instances = [];
    let closed = false;
    class Worker {
        constructor() {
            if (instances.length === 1) throw new Error("timer worker creation failed");
            instances.push(this);
        }
        postMessage(data) {
            if (data.type === "boot") queueMicrotask(() => this.onmessage({ data: { type: "booted" } }));
        }
        terminate() { this.terminated = true; }
    }
    const context = vm.createContext({ Worker, Atomics, setTimeout, clearTimeout,
        postMessage: (data) => output.push(data), close: () => { closed = true; } });
    vm.runInContext(source, context);
    await context.onmessage({ data: { type: "init", admissionTimeout: 1000 } });
    assert(!output.some(({ type }) => type === "ready"));
    assert.equal(output.at(-1).type, "fatal");
    assert.match(output.at(-1).error, /timer worker creation failed/);
    assert(instances.every(({ terminated }) => terminated));
    assert(closed);
});


test("missing timer exports reject event-worker bootstrap", async () => {
    const { timerDriver } = await import("../../src/browser/timer-driver.js");
    assert.throws(() => timerDriver({}), /timer exports/);
});

// Linking Wasm alone cannot catch a missing JS dependency that prevents the
// independent event driver from starting.
test("threaded host artifact recipe includes the worker's local module imports", async () => {
    const worker = await readFile(new URL("../../src/browser/worker.js", import.meta.url), "utf8");
    for (const recipe of ["./build.sh"]) {
        const script = await readFile(new URL(recipe, import.meta.url), "utf8");
        const assetList = script.match(/cp "\$host_dir"\/src\/browser\/\{([^}]+)\}\.js/);
        assert(assetList, `${recipe} must copy the host worker assets`);
        const assets = assetList[1].split(",");
        for (const [, dependency] of worker.matchAll(/from "\.\/([^"/]+)\.js"/g)) {
            assert(assets.includes(dependency), `${recipe} must bundle ${dependency}.js`);
        }
    }
});

test("coordinator routes I/O independently of a busy guest and retires it normally", async () => {
    const h = await setup({ ioModuleUrl: "io-driver.js" });
    assert.equal(h.instances[2].messages[0].role, "io");
    h.prepare(1); await flush(); h.instances[0].send({ type: "commit", id: 1 });
    h.instances[3].send({ type: "io-command", command: { type: "send", id: 7 } });
    assert.equal(h.instances[2].messages.at(-1).type, "io-command");
    assert.equal(h.instances[3].messages.at(-1).type, "run");
    h.instances[3].send({ type: "idle", id: 1 });
    await h.context.onmessage({ data: { type: "shutdown" } }); await flush();
    assert(h.instances.every(({ terminated }) => terminated));
    assert.equal(h.output.at(-1).type, "stopped");
});

test("worker failure preserves its Wasm stack for infrastructure diagnostics", async () => {
    const h = await setup();
    h.instances[0].onerror({ preventDefault() {}, message: "Uncaught trap", error: { stack: "RuntimeError: memory access out of bounds\n at runtime-frame" } });
    assert.equal(h.output.at(-1).error, "root worker 0 (idle): RuntimeError: memory access out of bounds\n at runtime-frame");
    assert(h.instances.every(({ terminated }) => terminated));
});

test("fatal cleanup settles in-flight bootstrap and releases worker and deadline roots", async () => {
    const h = await setup();
    h.control.holdBoot = true;
    const reply = h.prepare(1);
    assert.equal(vm.runInContext("bootWaiters.size", h.context), 1);
    h.instances[0].send({ type: "fatal", error: "root died during child bootstrap" });
    await flush();
    assert.equal(Atomics.load(reply, 0), 2);
    assert.equal(vm.runInContext("bootWaiters.size", h.context), 0);
    assert.equal(vm.runInContext("admissions.size", h.context), 0);
    assert.equal(vm.runInContext("root", h.context), null);
    assert.equal(vm.runInContext("timerWorker", h.context), null);
    assert.equal(vm.runInContext("ioWorker", h.context), null);
    assert(h.instances.every(({ terminated }) => terminated));
    assert.equal(h.output.filter(({ type }) => type === "fatal").length, 1);
});

test("uncaught bootstrap worker death poisons a heap with uncertain TLS initialization", async () => {
    const h = await setup();
    h.control.holdBoot = true;
    const reply = h.prepare(1);
    h.instances[2].onerror({ preventDefault() {}, message: "initializer trapped" });
    await flush();
    assert.equal(Atomics.load(reply, 0), 2);
    assert.equal(h.output.at(-1).type, "fatal");
    assert(h.instances.every(({ terminated }) => terminated));
    assert.equal(vm.runInContext("bootWaiters.size", h.context), 0);
});

test("normal shutdown releases root and service Worker references", async () => {
    const h = await setup({ ioModuleUrl: "io-driver.js", prewarm: 2, servicePrewarm: 1 });
    await h.context.onmessage({ data: { type: "shutdown" } });
    await flush();
    for (const name of ["root", "timerWorker", "ioWorker", "options"]) {
        assert.equal(vm.runInContext(name, h.context), null, name);
    }
    assert.equal(vm.runInContext("workers.size", h.context), 0);
});

test("copy realm replacement routes new clients only after direct handoff readiness", async () => {
    const h = await setup({ memoryCopyUrl: "copy-worker.js" });
    const old = h.instances[0], root = h.instances[1];
    old.send({ type: "rotate" });
    const next = h.instances[3];
    assert.equal(next.messages[0].type, "restore");
    assert.equal(old.messages.at(-1).type, "handoff");
    assert(!old.terminated);
    const reply = new Int32Array(new SharedArrayBuffer(4));
    root.send({ type: "prepare", id: 1, reply });
    await flush();
    assert.equal(Atomics.load(reply, 0), 1);
    assert.equal(next.messages.length, 1, "new connection waits for registry installation");
    assert.equal(vm.runInContext("copyRotation.ports.length", h.context), 1);
    next.send({ type: "ready" });
    assert.equal(old.messages.at(-1).type, "retire");
    assert(!old.terminated);
    assert.equal(next.messages.at(-1).type, "restore", "new clients wait for outgoing cleanup ACK");
    old.send({ type: "retired" });
    assert(old.terminated);
    assert.equal(next.messages.at(-1).type, "connect");
    assert.equal(vm.runInContext("copyRotation", h.context), null);
    assert.equal(vm.runInContext("copyRotations", h.context), 1);
    h.instances[1].send({ type: "fatal", error: "test finished" });
    assert(next.terminated);
});

for (const mode of ["failure", "shutdown-old-first", "shutdown-next-first", "timeout"]) {
    test(`copy realm ${mode} reclaims both realms, deadline and queued endpoints`, async () => {
        const shutdown = mode.startsWith("shutdown");
        const h = await setup({ memoryCopyUrl: "copy-worker.js", admissionTimeout: 20 });
        const old = h.instances[0];
        old.send({ type: "rotate" });
        const next = h.instances[3];
        const queued = { close() { this.closed = true; } };
        vm.runInContext("copyRotation.ports", h.context).push(queued);
        if (mode === "failure") next.onerror({ preventDefault() {}, message: "replacement died" });
        else if (shutdown) { await h.context.onmessage({ data: { type: "shutdown" } }); await flush(); }
        else await new Promise((resolve) => setTimeout(resolve, 40));
        for (const worker of [old, next]) {
            if (shutdown) {
                assert.equal(worker.messages.at(-1).type, "retire");
                assert(!worker.terminated);
            } else assert(worker.terminated);
        }
        if (shutdown) {
            assert(!h.output.some(data => data.type === "stopped"));
            next.send({ type: "ready" });
            const order = mode === "shutdown-old-first" ? [old, next] : [next, old];
            order[0].send({ type: "retired" });
            assert(!h.output.some(data => data.type === "stopped"), "both captured owners must acknowledge");
            order[1].send({ type: "retired" });
        }
        assert(queued.closed);
        assert.equal(vm.runInContext("copyRotation", h.context), null);
        assert.equal(h.output.at(-1).type, shutdown ? "stopped" : "fatal");
    });
}

test("restored copy owner has a fresh cleanup deadline after near-deadline readiness", async () => {
    const h = await setup({ memoryCopyUrl: "copy-worker.js", admissionTimeout: 20 });
    let now = 0, identity = 0;
    const timers = new Map();
    h.context.setTimeout = (callback, delay) => { const id = ++identity; timers.set(id, { at: now + delay, callback }); return id; };
    h.context.clearTimeout = id => timers.delete(id);
    const advance = delta => {
        now += delta;
        for (const [id, timer] of [...timers]) if (timer.at <= now) { timers.delete(id); timer.callback(); }
    };
    const old = h.instances[0];
    old.send({ type: "rotate" });
    const next = h.instances[3];
    advance(19);
    next.send({ type: "ready" });
    advance(2);
    assert(!h.output.some(data => data.type === "fatal"), "completed handoff deadline cannot interrupt cleanup");
    assert(!old.terminated);
    advance(17);
    old.send({ type: "retired" });
    assert.equal(vm.runInContext("memoryCopies", h.context), next);
    assert.equal(timers.size, 0);
    h.instances[1].send({ type: "fatal", error: "test finished" });
});

test("copy retirement deadline fails and hard-terminates the captured owner", async () => {
    const h = await setup({ memoryCopyUrl: "copy-worker.js", admissionTimeout: 20 });
    const copy = h.instances[0];
    await h.context.onmessage({ data: { type: "shutdown" } });
    await flush();
    assert(!copy.terminated);
    await new Promise(resolve => setTimeout(resolve, 40));
    assert.equal(h.output.at(-1).type, "fatal");
    assert.match(h.output.at(-1).error, /memory-copy retirement timed out/);
    assert(copy.terminated);
    assert.equal(vm.runInContext("memoryCopies", h.context), null);
});

test("rotation preserves receiver's deferred rotation and ignores the retired sender's late reply", async () => {
    const h = await setup({ memoryCopyUrl: "copy-worker.js" });
    const old = h.instances[0];
    old.send({ type: "rotate" });
    const next = h.instances[3];
    next.send({ type: "ready" });
    next.send({ type: "rotate" });
    const stale = old.onmessage;
    old.send({ type: "retired" });
    assert(old.terminated);
    assert.equal(vm.runInContext("memoryCopies", h.context), next);
    assert.equal(h.instances[4].messages[0].type, "restore");
    assert.equal(next.messages.at(-1).type, "handoff");
    stale({ data: { type: "retired" } });
    assert(!h.output.some(data => data.type === "fatal"));
    h.instances[1].send({ type: "fatal", error: "test finished" });
    assert(next.terminated);
    assert(h.instances[4].terminated);
});

test("unrequested copy retirement cannot acknowledge current ownership", async () => {
    const h = await setup({ memoryCopyUrl: "copy-worker.js" });
    h.instances[0].send({ type: "retired" });
    assert.equal(h.output.at(-1).type, "fatal");
    assert.match(h.output.at(-1).error, /unrequested memory-copy retirement/);
    assert(h.instances.every(worker => worker.terminated));
});

test("quiescent pool sweeps every object consumer and late replies preserve new admissions", async () => {
    const h = await setup({ prewarm: 2, servicePrewarm: 1, ioModuleUrl: "io-driver.js" });
    h.prepare(1);
    await flush();
    h.instances[0].send({ type: "commit", id: 1 });
    h.instances[0].send({ type: "result", result: "done" });
    assert(!h.instances.some(worker => worker.messages.some(({ type }) => type === "collect")));
    const task = h.instances.find(worker => worker.messages.some(({ type }) => type === "run"));
    task.send({ type: "idle", id: 1 });
    for (const worker of h.instances) {
        const role = worker.messages[0].role;
        assert.equal(worker.messages.at(-1).type === "collect", role !== "timer" && role !== "io", role);
    }
    h.prepare(2);
    await flush();
    task.send({ type: "collected" });
    h.instances[0].send({ type: "commit", id: 2 });
    assert.equal(task.messages.at(-1).type, "run");
    task.send({ type: "fatal", error: "test finished" });
});

async function completedTaskBatch(h, canRetire) {
    const task = h.instances[2];
    for (let id = 1; id <= 32; id++) {
        const reply = h.prepare(id);
        await flush();
        assert.equal(Atomics.load(reply, 0), 1);
        h.instances[0].send({ type: "commit", id });
        task.send({ type: "idle", id });
    }
    task.send({ type: "collected", canRetire });
    return task;
}

test("next admission replaces an aged task realm only after acknowledged TLS retirement", async () => {
    const h = await setup({ prewarm: 1 });
    const old = await completedTaskBatch(h, true);
    const reply = h.prepare(33);
    await flush();
    await flush();
    assert(old.terminated);
    assert.equal(Atomics.load(reply, 0), 1);
    assert.equal(h.instances.length, 4);
    assert.equal(h.instances[3].messages.at(-1).type, "prepare");
    assert.equal(vm.runInContext("taskRotations", h.context), 1);
    assert.equal(vm.runInContext("workers.size", h.context), 3, "replacement must preserve bounded capacity");
});

test("live engine roots prevent aged task replacement", async () => {
    const h = await setup({ prewarm: 1 });
    const old = await completedTaskBatch(h, false);
    const reply = h.prepare(33);
    await flush();
    assert(!old.terminated);
    assert.equal(h.instances.length, 3);
    assert.equal(Atomics.load(reply, 0), 1);
});

test("cancellation during realm replacement cannot dispatch the canceled start", async () => {
    const h = await setup({ prewarm: 1 });
    const old = await completedTaskBatch(h, true);
    h.control.holdRetire = true;
    const reply = h.prepare(33);
    await flush();
    assert.equal(old.messages.at(-1).type, "retire");
    Atomics.compareExchange(reply, 0, 0, 3);
    h.instances[0].send({ type: "cancel", id: 33 });
    old.send({ type: "retired" });
    await flush();
    await flush();
    assert.equal(Atomics.load(reply, 0), 3);
    assert(!h.instances[3].messages.some(({ type }) => type === "prepare" || type === "run"));
    assert.equal(vm.runInContext("admissions.size", h.context), 0);
});

test("uncertain retirement poisons instead of reusing its TLS allocation", async () => {
    const h = await setup({ prewarm: 1, admissionTimeout: 20 });
    await completedTaskBatch(h, true);
    h.control.holdRetire = true;
    const reply = h.prepare(33);
    await new Promise(resolve => setTimeout(resolve, 40));
    assert.equal(Atomics.load(reply, 0), 2);
    assert(h.instances.every(({ terminated }) => terminated));
    assert.equal(h.output.at(-1).type, "fatal");
});

test("retiring worker death settles the reserved admission and its deadline", async () => {
    const h = await setup({ prewarm: 1 });
    const old = await completedTaskBatch(h, true);
    h.control.holdRetire = true;
    const reply = h.prepare(33);
    await flush();
    const state = vm.runInContext("[...workers.values()].find(state => state.status === 'retiring')", h.context);
    old.onerror({ preventDefault() {}, message: "retiring worker died" });
    await flush();
    assert.equal(state.retirement, null);
    assert.equal(Atomics.load(reply, 0), 2);
    assert.equal(vm.runInContext("admissions.size", h.context), 0);
    assert(h.instances.every(({ terminated }) => terminated));
});

test("realm replacement reserves one admission without reducing remaining task capacity", async () => {
    const h = await setup({ prewarm: 2, taskLimit: 2 });
    const old = await completedTaskBatch(h, true);
    h.control.holdRetire = true;
    const replacement = h.prepare(33);
    await flush();
    const remaining = h.prepare(34);
    await flush();
    const full = h.prepare(35);
    await flush();
    assert.equal(Atomics.load(remaining, 0), 1);
    assert.equal(Atomics.load(full, 0), 2);
    old.send({ type: "retired" });
    await flush();
    await flush();
    assert.equal(Atomics.load(replacement, 0), 1);
    assert.equal(vm.runInContext("workers.size", h.context), 4);
});

for (const terminal of ["fatal", "stopped", "error", "messageerror"]) {
    test(`bootstrap disposes post-ready ${terminal} before notifying consumers`, async () => {
        const bootstrap = await readFile(new URL("../../src/browser/bootstrap.js", import.meta.url), "utf8");
        const instances = [];
        class Module {}
        class Memory { constructor() { this.buffer = new SharedArrayBuffer(4); } }
        class Worker {
            constructor() { instances.push(this); }
            postMessage() { queueMicrotask(() => this.onmessage({ data: { type: "ready" } })); }
            terminate() { this.terminations = (this.terminations ?? 0) + 1; }
        }
        const context = vm.createContext({ Worker, WebAssembly: { Module, Memory },
            SharedArrayBuffer, URL, location: { href: "https://example.test/" }, isSecureContext: true, crossOriginIsolated: true,
            setTimeout, clearTimeout });
        vm.runInContext(bootstrap.replace("export async function", "async function")
            .replaceAll("import.meta.url", '"https://example.test/bootstrap.js"'), context);
        const notices = [];
        const worker = await context.startCoordinator({ module: new Module(), memory: new Memory(),
            bindingsUrl: "https://example.test/runtime.js" }, data => {
            notices.push(data);
            if (data.type === "ready") return;
            assert.equal(instances[0].terminations, 1);
            for (const name of ["onmessage", "onerror", "onmessageerror"]) assert.equal(instances[0][name], null);
            throw new Error("consumer failed");
        });
        const stale = worker.onmessage;
        const notify = () => {
            if (terminal === "error") worker.onerror({ message: "coordinator died" });
            else if (terminal === "messageerror") worker.onmessageerror();
            else worker.onmessage({ data: { type: terminal, error: "test fatal" } });
        };
        assert.throws(notify, /consumer failed/);
        stale({ data: { type: "fatal", error: "late event" } });
        assert.equal(worker.terminations, 1);
        assert.equal(notices.length, 2, "queued terminal notifications cannot retain or notify consumers twice");
    });
}

test("queued boot success cannot dispatch into a subsequently poisoned heap", async () => {
    const h = await setup();
    h.control.holdBoot = true;
    const reply = h.prepare(1);
    const child = h.instances[2];
    child.send({ type: "booted" });
    h.instances[1].send({ type: "fatal", error: "timer died before boot continuation" });
    await flush();
    assert.equal(Atomics.load(reply, 0), 2);
    assert(!child.messages.some(({ type }) => type === "prepare"));
    assert(h.instances.every(({ terminated }) => terminated));
    assert.equal(vm.runInContext("admissions.size", h.context), 0);
});

test("stopped before ready settles bootstrap instead of canceling its only deadline", async () => {
    const bootstrap = await readFile(new URL("../../src/browser/bootstrap.js", import.meta.url), "utf8");
    const instances = [];
    class Module {}
    class Memory { constructor() { this.buffer = new SharedArrayBuffer(4); } }
    class Worker {
        constructor() { instances.push(this); }
        postMessage() {}
        terminate() { this.terminated = true; }
    }
    const context = vm.createContext({ Worker, WebAssembly: { Module, Memory }, SharedArrayBuffer, URL,
        location: { href: "https://example.test/" }, isSecureContext: true, crossOriginIsolated: true,
        setTimeout, clearTimeout });
    vm.runInContext(bootstrap.replace("export async function", "async function")
        .replaceAll("import.meta.url", '"https://example.test/bootstrap.js"'), context);
    const starting = context.startCoordinator({ module: new Module(), memory: new Memory(),
        bindingsUrl: "https://example.test/runtime.js", admissionTimeout: 20 });
    instances[0].onmessage({ data: { type: "stopped" } });
    await assert.rejects(starting, /stopped during bootstrap/);
    assert(instances[0].terminated);
});

test("fatal initialization cannot restore root or driver references after cleanup", async () => {
    for (const failedRole of ["root", "timer", "io", "task", "service"]) {
        const output = [], instances = [];
        class Worker {
            constructor() { instances.push(this); }
            postMessage(data) {
                if (data.type !== "boot") return;
                queueMicrotask(() => {
                    this.onmessage({ data: { type: "booted" } });
                    if (data.role === failedRole) this.onmessage({ data: { type: "fatal", error: "initialization failed" } });
                });
            }
            terminate() { this.terminated = true; }
        }
        const context = vm.createContext({ Worker, Atomics, setTimeout, clearTimeout,
            postMessage: data => output.push(data), close() {} });
        vm.runInContext(source, context);
        await context.onmessage({ data: { type: "init", ioModuleUrl: "io.js", prewarm: 1,
            servicePrewarm: 1, admissionTimeout: 1000 } });
        assert.equal(output.filter(({ type }) => type === "fatal").length, 1);
        assert(!output.some(({ type }) => type === "ready"), failedRole);
        for (const name of ["root", "timerWorker", "ioWorker", "options"]) {
            assert.equal(vm.runInContext(name, context), null, failedRole + ": " + name);
        }
        assert(instances.every(({ terminated }) => terminated));
    }
});

test("owner abort discards busy workers and ignores late initialization", async () => {
    const h = await busyTask();
    h.task.send({ type: "watch-word", ticket: 1, address: 0, observed: 0 });
    await h.context.onmessage({ data: { type: "abort", error: "process killed" } });
    assert(h.instances.every(worker => worker.terminated));
    assert.equal(h.output.at(-1).type, "fatal");
    assert.equal(h.output.at(-1).error, "process killed");
    assert.equal(h.output.at(-1).ownerAbort, true);
    assert.equal(vm.runInContext("workers.size + admissions.size + wordWaiters.size", h.context), 0);
    assert.equal(vm.runInContext("options", h.context), null);
    assert(h.control.closed);
    const count = h.instances.length;
    await h.context.onmessage({ data: { type: "init", workerUrl: "stale.js" } });
    await h.context.onmessage({ data: { type: "abort" } });
    h.task.send({ type: "idle", id: 1 });
    assert.equal(h.instances.length, count);
    assert.equal(h.output.filter(data => data.type === "fatal").length, 1);
});

test("owner abort cancels unaccepted admission and terminates copy worker", async () => {
    const h = await setup({ memoryCopyUrl: "copy-worker.js" });
    h.control.hold = true;
    const reply = new Int32Array(new SharedArrayBuffer(4));
    h.instances[1].send({ type: "prepare", id: 1, reply });
    await flush();
    assert.equal(Atomics.load(reply, 0), 0);
    await h.context.onmessage({ data: { type: "abort" } });
    assert.equal(Atomics.load(reply, 0), 2);
    assert(h.instances.every(worker => worker.terminated));
    assert.equal(vm.runInContext("memoryCopies", h.context), null);
    assert.equal(h.output.at(-1).error, "runtime aborted by its owner");
});

for (const stage of ["before", "booting", "ready"]) {
    test(`bootstrap cancellation owns heap discard ${stage} readiness`, async () => {
        const bootstrap = await readFile(new URL("../../src/browser/bootstrap.js", import.meta.url), "utf8");
        const instances = [], notices = [];
        class Module {}
        class Memory { constructor() { this.buffer = new SharedArrayBuffer(4); } }
        class Worker {
            constructor() { this.messages = []; instances.push(this); }
            postMessage(data) { this.messages.push(data); }
            terminate() { this.terminations = (this.terminations ?? 0) + 1; }
        }
        const context = vm.createContext({ Worker, WebAssembly: { Module, Memory },
            SharedArrayBuffer, URL, location: { href: "https://example.test/" }, isSecureContext: true,
            crossOriginIsolated: true, setTimeout, clearTimeout });
        vm.runInContext(bootstrap.replace("export async function", "async function")
            .replaceAll("import.meta.url", '"https://example.test/bootstrap.js"'), context);
        const controller = new AbortController();
        const reason = { original: "owner aborted" };
        if (stage === "before") controller.abort(reason);
        let settled = false;
        const pending = context.startCoordinator({ module: new Module(), memory: new Memory(),
            bindingsUrl: "https://example.test/runtime.js", signal: controller.signal }, data => notices.push(data));
        void pending.then(() => { settled = true; }, () => { settled = true; });
        if (stage === "before") {
            await assert.rejects(pending, error => error === reason);
            assert.equal(instances.length, 0);
            return;
        }
        const worker = instances[0];
        assert.equal(worker.messages[0].type, "init");
        assert(!("signal" in worker.messages[0]), "AbortSignal must not cross structured clone");
        if (stage === "ready") {
            worker.onmessage({ data: { type: "ready" } });
            assert.equal(await pending, worker);
        }
        controller.abort(reason);
        assert.equal(worker.messages.at(-1).type, "abort");
        assert.equal(worker.terminations, undefined, "coordinator still owns child cleanup");
        if (stage === "booting") {
            worker.onmessage({ data: { type: "ready" } });
            await flush();
            assert.equal(settled, false, "late readiness cannot publish canceled bootstrap");
            assert.equal(notices.length, 0);
        }
        worker.onmessage({ data: { type: "fatal", error: "runtime aborted by its owner", ownerAbort: true } });
        if (stage === "booting") await assert.rejects(pending, error => error === reason);
        assert.equal(worker.terminations, 1);
        assert.equal(worker.onmessage, null);
        assert.equal(notices.at(-1).type, "fatal");
    });
}


for (const failure of ["fatal", "deadline"]) {
    test(`bootstrap abort preserves unrelated ${failure} failure`, async () => {
        const bootstrap = await readFile(new URL("../../src/browser/bootstrap.js", import.meta.url), "utf8");
        const instances = [];
        class Module {}
        class Memory { constructor() { this.buffer = new SharedArrayBuffer(4); } }
        class Worker {
            constructor() { instances.push(this); }
            postMessage() {}
            terminate() { this.terminated = true; }
        }
        const context = vm.createContext({ Worker, WebAssembly: { Module, Memory },
            SharedArrayBuffer, URL, location: { href: "https://example.test/" }, isSecureContext: true,
            crossOriginIsolated: true, setTimeout, clearTimeout });
        vm.runInContext(bootstrap.replace("export async function", "async function")
            .replaceAll("import.meta.url", '"https://example.test/bootstrap.js"'), context);
        const controller = new AbortController();
        const reason = { original: "requested cancellation" };
        const pending = context.startCoordinator({ module: new Module(), memory: new Memory(),
            bindingsUrl: "https://example.test/runtime.js", signal: controller.signal,
            admissionTimeout: 20 });
        const expected = failure === "fatal" ? "timer worker died" : "coordinator bootstrap timed out";
        const rejected = assert.rejects(pending, error => error !== reason && error.message === expected);
        controller.abort(reason);
        if (failure === "fatal") instances[0].onmessage({ data: { type: "fatal", error: expected } });
        await rejected;
        assert(instances[0].terminated);
        assert.equal(instances[0].onmessage, null);
    });
}

test("worker failure cannot claim owner abort attribution", async () => {
    const h = await busyTask();
    h.task.send({ type: "fatal", error: "worker died", ownerAbort: true });
    assert.equal(h.output.at(-1).type, "fatal");
    assert.equal(h.output.at(-1).ownerAbort, undefined);
    assert(h.instances.every(worker => worker.terminated));
});

// Same bootstrap as the browser controls, without installing browser security,
// location or Worker globals. These protocol fixtures do not claim native exit.
async function hostBootstrapFixture() {
    const bootstrap = await readFile(new URL("../../src/browser/bootstrap.js", import.meta.url), "utf8");
    class Module {}
    class Memory { constructor(buffer = new SharedArrayBuffer(4)) { this.buffer = buffer; } }
    const context = vm.createContext({ WebAssembly: { Module, Memory }, SharedArrayBuffer,
        URL, setTimeout, clearTimeout });
    vm.runInContext(bootstrap.replace("export async function", "async function")
        .replaceAll("import.meta.url", '"file:///runtime/bootstrap.js"'), context);
    return { context, options: { module: new Module(), memory: new Memory(), bindingsUrl: "runtime.js",
        taskLimit: 2, serviceLimit: 1, prewarm: 0, servicePrewarm: 0 }, Memory };
}

test("explicit host resolves URLs without browser globals and stays outside cloneable config", async () => {
    const { context, options } = await hostBootstrapFixture();
    let worker, created = 0;
    const host = { baseURL: "file:///sdk/assets/", createWorker(url, settings) {
        created++;
        assert.equal(url.href, "file:///runtime/coordinator.js");
        assert.equal(settings.type, "module");
        worker = { messages: [], terminations: 0,
            postMessage(data) {
                this.messages.push(data);
                queueMicrotask(() => this.onmessage({ data: { type: "ready" } }));
            },
            terminate() { this.terminations++; },
        };
        return worker;
    } };
    const returned = await context.startCoordinator({ ...options, ioModuleUrl: "io.js",
        memoryCopyUrl: "memory/copy.js" }, () => {}, host);
    assert.equal(returned, worker);
    assert.equal(created, 1);
    const config = worker.messages[0];
    assert.equal(config.bindingsUrl, "file:///sdk/assets/runtime.js");
    assert.equal(config.ioModuleUrl, "file:///sdk/assets/io.js");
    assert.equal(config.memoryCopyUrl, "file:///sdk/assets/memory/copy.js");
    assert.equal(config.memoryClientUrl, "file:///sdk/assets/memory/client.js");
    for (const key of ["host", "baseURL", "createWorker"]) assert(!(key in config));
    for (const key of ["location", "Worker", "isSecureContext", "crossOriginIsolated"]) {
        assert.equal(vm.runInContext(`typeof ${key}`, context), "undefined");
    }
    worker.onmessage({ data: { type: "stopped" } });
    assert.equal(worker.terminations, 1);
});

test("explicit host retains module, shared-memory, URL and capacity validation before factory admission", async () => {
    const { context, options, Memory } = await hostBootstrapFixture();
    let created = 0;
    const host = { baseURL: "file:///sdk/", createWorker() { created++; throw new Error("unexpected factory admission"); } };
    await assert.rejects(context.startCoordinator({ ...options, module: {} }, () => {}, host), /compiled runtime module/);
    await assert.rejects(context.startCoordinator({ ...options, memory: new Memory(new ArrayBuffer(4)) }, () => {}, host), /shared runtime memory/);
    await assert.rejects(context.startCoordinator({ ...options, taskLimit: -1 }, () => {}, host), /capacity/);
    await assert.rejects(context.startCoordinator({ ...options, stackSize: 1 }, () => {}, host), /stack size/);
    await assert.rejects(context.startCoordinator(options, () => {}, { ...host, baseURL: "relative/" }), /Invalid URL/);
    await assert.rejects(context.startCoordinator(options, () => {}, {}), /Worker factory/);
    assert.equal(created, 0);
    const original = new Error("synchronous native constructor failure");
    await assert.rejects(context.startCoordinator(options, () => {}, { ...host,
        createWorker() { throw original; } }), error => error === original);
});

for (const failure of ["error", "messageerror", "fatal", "abort"]) {
    test(`explicit host joins its owned retirement after bootstrap ${failure} and ignores stale reentry`, async () => {
        const { context, options } = await hostBootstrapFixture();
        const controller = new AbortController();
        const original = new Error("original owner cancellation");
        let release, worker;
        const exited = new Promise(resolve => { release = resolve; });
        const host = { baseURL: "file:///sdk/", createWorker() {
            worker = { messages: [], terminations: 0, exited,
                postMessage(data) { this.messages.push(data); },
                terminate() { this.terminations++; return exited; },
            };
            return worker;
        } };
        const pending = context.startCoordinator({ ...options, signal: controller.signal }, () => {}, host);
        let settled = false;
        pending.then(() => { settled = true; }, () => { settled = true; });
        const stale = worker.onmessage;
        const staleError = worker.onerror;
        if (failure === "error") worker.onerror({ message: "native worker failed" });
        else if (failure === "messageerror") worker.onmessageerror();
        else {
            if (failure === "abort") controller.abort(original);
            worker.onmessage({ data: { type: "fatal", error: "native worker failed", ownerAbort: failure === "abort" } });
        }
        assert.equal(worker.terminations, 1);
        for (const name of ["onmessage", "onerror", "onmessageerror"]) assert.equal(worker[name], null);
        stale({ data: { type: "ready" } });
        staleError({ message: "stale reentrant error" });
        controller.abort(original);
        await flush();
        assert.equal(settled, false, "requesting native termination is not its completion");
        release(1);
        await assert.rejects(pending, error => failure === "abort" ? error === original
            : error.message === (failure === "messageerror" ? "coordinator message could not be decoded" : "native worker failed"));
        assert.equal(worker.terminations, 1);
    });
}

test("synchronous cleanup failure cannot replace the original bootstrap dispatch error", async () => {
    const { context, options } = await hostBootstrapFixture();
    const original = new Error("original init dispatch failure");
    let worker;
    const host = { baseURL: "file:///sdk/", createWorker() {
        return worker = { terminations: 0,
            postMessage() { throw original; },
            terminate() { this.terminations++; throw new Error("secondary cleanup failure"); },
        };
    } };
    await assert.rejects(context.startCoordinator(options, () => {}, host), error => error === original);
    assert.equal(worker.terminations, 1);
    assert.equal(worker.onmessage, null);
});

for (const ready of [false, true]) {
    for (const code of [0, 1]) {
        test(`native exit ${code} ${ready ? "after" : "before"} readiness cannot replace protocol shutdown`, async () => {
            const { context, options } = await hostBootstrapFixture();
            let exit, worker;
            const exited = new Promise(resolve => { exit = resolve; });
            const notices = [];
            const host = { baseURL: "file:///sdk/", createWorker() {
                return worker = { exited, terminations: 0,
                    postMessage() {}, terminate() { this.terminations++; return exited; },
                };
            } };
            const pending = context.startCoordinator(options, data => notices.push(data), host);
            if (ready) {
                worker.onmessage({ data: { type: "ready" } });
                assert.equal(await pending, worker);
            }
            // Even exit zero with an intentional host-close marker is not the
            // required B2 ready/stopped/ownerAbort acknowledgement.
            exit(code);
            if (!ready) await assert.rejects(pending, new RegExp(`before protocol shutdown with status ${code}`));
            await flush();
            assert.equal(worker.terminations, 1);
            assert.equal(notices.at(-1).type, "fatal");
            assert.match(notices.at(-1).error, /before protocol shutdown/);
        });
    }
}

test("a rejected native termination promise retains the original bootstrap failure", async () => {
    const { context, options } = await hostBootstrapFixture();
    const original = new Error("original dispatch error with asynchronous cleanup");
    let worker;
    const host = { baseURL: "file:///sdk/", createWorker() {
        return worker = { terminations: 0,
            postMessage() { throw original; },
            terminate() { this.terminations++; return Promise.reject(new Error("secondary terminate rejection")); },
        };
    } };
    await assert.rejects(context.startCoordinator(options, () => {}, host), error => error === original);
    assert.equal(worker.terminations, 1);
});

for (const operation of ["throw", "dispatch-clone-error"]) {
    test(`native host Ready callback ${operation} retains its actual worker until exit`, { timeout: 5000 }, async () => {
        const { context, options } = await hostBootstrapFixture();
        const asset = new URL(`data:text/javascript,${encodeURIComponent(`
            import { parentPort } from 'node:worker_threads';
            parentPort.on('message', () => parentPort.postMessage({ type: 'ready' }));
        `)}`);
        let owner, callbackError, exited = false;
        const original = new Error("original Ready callback error");
        const host = { baseURL: "file:///sdk/", createWorker(url) {
            const native = new NativeWorker(url);
            const exit = new Promise(resolve => native.once("exit", code => { exited = true; resolve(code); }));
            owner = { exited: exit, terminations: 0,
                postMessage(message) { native.postMessage(message); },
                terminate() { this.terminations++; return native.terminate().then(() => exit); },
            };
            native.on("message", data => owner.onmessage?.({ data }));
            native.on("error", error => owner.onerror?.({ error, message: error.message }));
            return owner;
        } };
        try {
            await assert.rejects(context.startCoordinator({ ...options, coordinatorUrl: asset.href }, data => {
                if (data.type !== "ready") return;
                try {
                    if (operation === "throw") throw original;
                    owner.postMessage(() => {});
                } catch (error) { callbackError = error; throw error; }
            }, host), error => error === callbackError);
            assert.ok(callbackError);
            if (operation === "throw") assert.equal(callbackError, original);
            else assert.equal(callbackError.name, "DataCloneError");
            assert.equal(exited, true, "failed bootstrap must join the real native worker exit");
            assert.equal(owner.terminations, 1);
        } finally { if (owner && !exited) await owner.terminate(); }
    });
}

for (const operation of ["fatal", "abort"]) {
    test(`explicit host Ready callback reentrant ${operation} cannot publish a healthy coordinator`, async () => {
        const { context, options } = await hostBootstrapFixture();
        const controller = new AbortController();
        const original = new Error("reentrant owner cancellation");
        let worker, release;
        const exited = new Promise(resolve => { release = resolve; });
        const host = { baseURL: "file:///sdk/", createWorker() {
            return worker = { terminations: 0, messages: [], exited,
                postMessage(data) { this.messages.push(data); },
                terminate() { this.terminations++; return exited; },
            };
        } };
        const pending = context.startCoordinator({ ...options, signal: controller.signal }, data => {
            if (data.type !== "ready") return;
            if (operation === "abort") controller.abort(original);
            else worker.onmessage({ data: { type: "fatal", error: "reentrant infrastructure failure" } });
        }, host);
        let settled = false;
        pending.then(() => { settled = true; }, () => { settled = true; });
        worker.onmessage({ data: { type: "ready" } });
        await flush();
        assert.equal(settled, false);
        if (operation === "abort") {
            assert.equal(worker.terminations, 0);
        }
        if (operation === "abort") {
            worker.onmessage({ data: { type: "fatal", ownerAbort: true, error: "runtime aborted by its owner" } });
        }
        release(0);
        await assert.rejects(pending, error => operation === "abort" ? error === original
            : error.message === "reentrant infrastructure failure");
        assert.equal(worker.terminations, 1);
    });
}

test("native coordinator exit zero without Ready rejects after actual native retirement", { timeout: 5000 }, async () => {
    const { context, options } = await hostBootstrapFixture();
    const asset = new URL(`data:text/javascript,${encodeURIComponent(`
        import { parentPort } from 'node:worker_threads';
        parentPort.once('message', () => process.exit(0));
    `)}`);
    let owner, observed;
    const host = { baseURL: "file:///sdk/", createWorker(url) {
        const native = new NativeWorker(url);
        const exited = new Promise(resolve => native.once("exit", code => { observed = code; resolve(code); }));
        owner = { exited, postMessage(data) { native.postMessage(data); },
            terminate() { return native.terminate().then(() => exited); },
        };
        native.on("message", data => owner.onmessage?.({ data }));
        native.on("error", error => owner.onerror?.({ error, message: error.message }));
        return owner;
    } };
    try {
        await assert.rejects(context.startCoordinator({ ...options, coordinatorUrl: asset.href }, () => {}, host),
            /before protocol shutdown with status 0/);
        assert.equal(observed, 0, "native success alone must not fabricate B2 readiness");
    } finally { if (owner && observed === undefined) await owner.terminate(); }
});

test("terminate rejection cannot release an independently owned native exit before original failure", async () => {
    const { context, options } = await hostBootstrapFixture();
    const original = new Error("first dispatch failure");
    let release;
    const exited = new Promise(resolve => { release = resolve; });
    const host = { baseURL: "file:///sdk/", createWorker() {
        return { exited, postMessage() { throw original; },
            terminate() { return Promise.reject(new Error("secondary terminate failure")); },
        };
    } };
    const pending = context.startCoordinator(options, () => {}, host);
    let settled = false;
    pending.then(() => { settled = true; }, () => { settled = true; });
    await flush();
    assert.equal(settled, false);
    release(1);
    await assert.rejects(pending, error => error === original);
});

test("native fatal notification callback throw cannot escape or replace the original failure", { timeout: 5000 }, async () => {
    const { context, options } = await hostBootstrapFixture();
    const asset = new URL(`data:text/javascript,${encodeURIComponent(`
        import { parentPort } from 'node:worker_threads';
        parentPort.once('message', () => {
            parentPort.postMessage({ type: 'fatal', error: 'original native protocol failure' });
        });
        parentPort.on('message', () => {});
    `)}`);
    let owner, nativeExited = false, callbacks = 0;
    const host = { baseURL: "file:///sdk/", createWorker(url) {
        const native = new NativeWorker(url);
        const exited = new Promise(resolve => native.once("exit", code => { nativeExited = true; resolve(code); }));
        owner = { exited, postMessage(data) { native.postMessage(data); },
            terminate() { return native.terminate().then(() => exited); },
        };
        native.on("message", data => owner.onmessage?.({ data }));
        native.on("error", error => owner.onerror?.({ error, message: error.message }));
        return owner;
    } };
    try {
        await assert.rejects(context.startCoordinator({ ...options, coordinatorUrl: asset.href }, data => {
            assert.equal(data.type, "fatal"); callbacks++;
            throw new Error("secondary fatal consumer callback failure");
        }, host), /original native protocol failure/);
        assert.equal(callbacks, 1);
        assert.equal(nativeExited, true);
    } finally { if (owner && !nativeExited) await owner.terminate(); }
});

for (const failure of ["error", "messageerror"]) {
    test(`explicit host ${failure} preserves first failure through throwing notification and gated exit`, async () => {
        const { context, options } = await hostBootstrapFixture();
        let worker, release;
        const exited = new Promise(resolve => { release = resolve; });
        const host = { baseURL: "file:///sdk/", createWorker() {
            return worker = { exited, postMessage() {}, terminate() { return exited; } };
        } };
        const pending = context.startCoordinator(options, () => {
            throw new Error("secondary consumer callback failure");
        }, host);
        let settled = false;
        pending.then(() => { settled = true; }, () => { settled = true; });
        assert.doesNotThrow(() => failure === "error"
            ? worker.onerror({ message: "original native event error" }) : worker.onmessageerror());
        await flush();
        assert.equal(settled, false);
        release(1);
        await assert.rejects(pending, error => error.message === (failure === "error"
            ? "original native event error" : "coordinator message could not be decoded"));
    });
}


// The optional terminal receipt is caller-local; ordinary callback data remains
// cloneable and one-argument consumers never receive a worker-wire Promise.
for (const terminalKind of ["native", "generic"]) {
    test(`bootstrap ${terminalKind} notice retains one caller-local retirement receipt and cloneable first data`, async () => {
        const { context, options } = await hostBootstrapFixture();
        let worker, receive, resolveExit, resolveTerminate;
        const exited = new Promise(done => { resolveExit = done; });
        const terminating = new Promise(done => { resolveTerminate = done; });
        const original = vm.runInContext('new Error("actual native error identity")', context);
        const notices = [];
        const host = { baseURL: "file:///sdk/", createWorker() {
            return worker = { exited, terminations: 0, postMessage() {},
                terminate() { this.terminations++; receive({ data: { type: "fatal", error: "stale reentry" } }); return terminating; } };
        } };
        const opening = context.startCoordinator(options, (data, terminal) => notices.push({ data, terminal }), host);
        receive = worker.onmessage;
        worker.onmessage({ data: { type: "ready" } }); await opening;
        if (terminalKind === "native") worker.onerror({ message: original.message, error: original });
        else worker.onmessage({ data: { type: "fatal", error: "generic protocol failure" } });
        const notice = notices.at(-1);
        assert.equal(notice.data.type, "fatal");
        assert.equal(notice.data.nativeWorkerFailure, undefined);
        assert.deepEqual(structuredClone(notice.data), { type: "fatal", error: terminalKind === "native" ? original.message : "generic protocol failure" });
        assert.equal(notice.terminal.origin, terminalKind === "native" ? "native-worker" : undefined);
        assert.equal(notice.terminal.originalError, terminalKind === "native" ? original : undefined);
        assert.equal(typeof notice.terminal.retirement.then, "function");
        const receipt = notice.terminal.retirement;
        let settled = false; receipt.then(() => { settled = true; });
        await flush(); assert.equal(worker.terminations, 1); assert.equal(settled, false);
        resolveTerminate(); await flush(); assert.equal(settled, false);
        resolveExit(0); await receipt;
        receive({ data: { type: "fatal", error: "late terminal" } });
        assert.equal(worker.terminations, 1); assert.equal(notices.length, 2);
        assert.equal(notice.terminal.retirement, receipt);
    });
}

for (const failure of ["terminate-throws", "terminate-rejects", "exit-rejects"]) {
    test(`bootstrap terminal receipt joins both captured retirement parts when ${failure}`, async () => {
        const { context, options } = await hostBootstrapFixture();
        let worker, resolveExit, rejectExit, resolveTerminate, rejectTerminate, receipt;
        const exited = new Promise((done, fail) => { resolveExit = done; rejectExit = fail; });
        const terminating = new Promise((done, fail) => { resolveTerminate = done; rejectTerminate = fail; });
        const original = new Error(failure);
        let stale;
        const opening = context.startCoordinator(options, (_data, terminal) => { if (terminal) receipt = terminal.retirement; },
            { baseURL: "file:///sdk/", createWorker() {
                return worker = { exited, terminations: 0, postMessage() {}, terminate() {
                    this.terminations++; stale({ data: { type: "fatal", error: "reentrant terminal" } });
                    if (failure === "terminate-throws") throw original;
                    return terminating;
                } };
            } });
        stale = worker.onmessage;
        worker.onmessage({ data: { type: "ready" } }); await opening;
        worker.onmessageerror();
        let settled = false;
        const rejected = assert.rejects(receipt, error => error === original).then(() => { settled = true; });
        if (failure === "exit-rejects") { resolveTerminate(); await flush(); assert.equal(settled, false); rejectExit(original); }
        else { if (failure === "terminate-rejects") rejectTerminate(original); await flush(); assert.equal(settled, false); resolveExit(0); }
        await rejected; assert.equal(worker.terminations, 1);
        assert.equal(worker.onmessage, null);
    });
}

test("only an actual live captured child worker error creates native fatal origin", async () => {
    const actual = await busyTask();
    actual.task.onerror({ message: "actual task worker died", preventDefault() {} });
    assert.equal(actual.output.at(-1).nativeWorkerFailure, true);
    const forged = await busyTask();
    forged.task.send({ type: "fatal", error: "guest message is not native evidence", nativeWorkerFailure: true });
    assert.equal(forged.output.at(-1).nativeWorkerFailure, undefined);
    const stale = await busyTask();
    const oldError = stale.task.onerror;
    stale.task.send({ type: "idle", id: 1 });
    await stale.context.onmessage({ data: { type: "shutdown" } });
    await flush();
    const count = stale.output.length;
    oldError({ message: "retired generation", preventDefault() {} });
    assert.equal(stale.output.length, count);
});


for (const requestThrows of [false, true]) {
    test(`READY lends only the existing disposal function, reentrant request ${requestThrows ? "throws" : "succeeds"}`, async () => {
        const { context, options } = await hostBootstrapFixture();
        let worker, receipt, resolveExit, stale, dispose;
        const exited = new Promise(done => { resolveExit = done; });
        const cleanup = new Error("synchronous request failure");
        const opening = context.startCoordinator(options, (data, local) => {
            if (data.type !== "ready") return;
            assert.deepEqual(Object.keys(local), ["retire"]);
            assert.equal(typeof local.retire, "function"); assert.equal(local.retirement, undefined);
            dispose = local.retire;
            receipt = dispose(); assert.equal(dispose(), receipt); receipt.catch(() => {});
        }, { baseURL: "file:///sdk/", createWorker() {
            return worker = { exited, terminations: 0, postMessage() {}, terminate() {
                this.terminations++; stale({ data: { type: "ready" } });
                if (requestThrows) throw cleanup;
            } };
        } });
        stale = worker.onmessage;
        worker.onmessage({ data: { type: "ready" } });
        let settled = false;
        const failed = assert.rejects(opening, /disposed during bootstrap/).then(() => { settled = true; });
        await flush(); assert.equal(settled, false); assert.equal(worker.terminations, 1);
        resolveExit(0); await failed;
        if (requestThrows) await assert.rejects(receipt, error => error === cleanup); else await receipt;
        assert.equal(dispose(), receipt); assert.equal(worker.terminations, 1);
    });
}
