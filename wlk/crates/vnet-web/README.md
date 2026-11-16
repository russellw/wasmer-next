# Browser relay backend

`WebBackend` implements vnet's existing `Backend`, `BackendStream` and
`BackendDatagram`. It owns no engine objects and changes no guest ABI or
kernel/exec contract. The kernel retains routes, namespaces, bind conflicts,
local sockets, DNS protocol handling and accept-queue policy.

Construct a backend and driver with explicit `Capabilities` and `Config` limits.
Run `Driver::run(transport)` on an independent I/O worker. A worker-local
`Transport` implements ordered command submission, event reception, independent
connection-health polling and idempotent close. It has no Send bound; JS objects
never enter the shared backend. Dropping the run future closes its transport,
fails pending operations and wakes the original guest wait queues. Manual
`Driver::poll` users must close their transport on cancellation themselves.

`Classic<T: FrameTransport>` translates whole binary websocket messages using the
v1 relay's bincode legacy tags and layouts. Native-only development dependencies
check these bytes against the reference types and exercise the actual
`RemoteNetworkingServer` over bounded framed channels and loopback TCP/UDP/DNS
on IPv4 and IPv6. Production dependencies contain no v1 runtime or Tokio.
The local relay fixture does not exercise a browser WebSocket implementation.

For WISP, the SDK's callback adapter implements `Transport` and uses
`Capabilities::wisp(ipv6)`: TCP and name resolution only, with no UDP or ingress.
The adapter translates successful sends to `Sent`, refused/failed operations to
explicit errno events, and provider EOF/reset to distinct events. Resolver
providers can opt into reverse and raw-forward DNS and return the corresponding
`Found` answer forms (for example through configured DoH). WISP protocol bytes
never go through the classic codec. This crate provides the provider contract;
JS callbacks, endpoint authentication/selection, CORS and worker bootstrap belong
to the embedding SDK/B2 integration.

Queue and lifecycle rules:

- Stream writes are partial and bounded. One send per flow is outstanding; a short
  `Sent` removes only its accepted prefix. EAGAIN waits for a provider `Writable`
  event, without busy retrying. FIN follows all accepted bytes.
- Receive queues are bounded. The driver retains at most one additional bounded
  relay frame while a reader is full, then resumes after a read wakes it. With the
  classic multiplexed protocol this backpressures subsequent frames for all flows;
  independent transport-health polling still detects disconnect. The JS adapter
  must also bound its own event queue and WebSocket `bufferedAmount`.
- UDP preserves empty messages, source addresses, peek and full lengths for
  truncation. Excess receive datagrams are dropped. Outgoing datagrams are bounded
  and released once the transport takes them; classic UDP has no success ACK.
- Dropping the last stream reference drains accepted writes before close, or aborts
  on unread data. Dropped publications close reserved and late-accepted children.
  Ingress leaves connections in the relay backlog while `poll_room` is Full;
  Gone accepts and resets, and Ready offers the connection to the guest. Sink
  calls and guest wakeups occur outside the backend mutex.
- Transport failure uses ECONNABORTED for affected sockets, not an invented peer
  reset. Reconnect accepts new sockets; old handles remain failed and no bytes are
  replayed. Pending resolver callbacks complete exactly once, outside locks.

## Protocol limits and follow-ups

### Opt-in namespace stream endpoints

`backend.clone().with_namespace_endpoints()` exposes the canonical endpoint
provider on the same backend and Driver. Only transports explicitly advertising
`selected_endpoints` support its transactions. `selected_bind` additionally
means real prebound resources: BindStream carries the original literal request
and purpose, then ConnectFrom/ListenFrom transfer the same socket ID. A direct
unbound listen uses its original Listen purpose; an unbound connection emits no
bind. Profiles without physical prebind keep canonical namespace reservation and
create ListenReserved at publication, retaining the original literal request
separately from its actual canonical nonzero port.

ConnectFrom additionally retains the canonical `local` reservation allocated by
the existing Net port table. It is distinct from the original requested bind
and physical `bound_addr`: virtual transports use the existing reserved source
port rather than inventing another allocator, while an unbound physical factory
keeps its actual any:0 source selection/readback. The Classic wire remains its
original unbound connect(any:0, peer) or same-bound ConnectBound operation.

Selected readiness uses canonical accepted-and-ready publication status before
accept credit. AcceptedTo retains the actual peer and destination; a Classic
selected accept instead queries the accepted child's GetAddrLocal. One accepted
child per listener may wait for the actual canonical backlog queue, without
invented source/destination addresses. Callback/ingress calls and wakes occur
outside backend locks. This is independent of default Backend publication.

Keep driving the same Driver while awaiting `close_endpoints()`. It revokes new
selected admission and joins cached, request-qualified local close results.
Sending CloseSelected does not finish close. Actual ProviderCloseAck confirms
physical retirement; LocalCloseUnconfirmed attests only the joined local
session described below. An adapter may map the existing Classic
request-qualified Close response to physical confirmation only with a matching
server ownership guarantee: the stock server has no
provisional-create cancellation record, so InvalidFd cannot acknowledge an
unfinished create or prove that a late remote resource has retired. Dropping a wait
subscription withdraws its registration and leaves cleanup owned by the driver.
Its `SelectedCloseReport::remote_cleanup_unconfirmed` records the original
Classic boundary independently of a successful local close. The first actual
cleanup errno is preserved. A pending old create/accept receipt stays in its
existing bounded Flow/Listener while the connection can still deliver it; a
late successful result owns cleanup of that same ID, never a replay of guest
creation. A stock `Complete`/InvalidFd response supplies no false promise that
an accepted notification cannot arrive.

`ProviderCloseAck.accept_pending` describes only notification custody. False
requires withdrawing/joining the unfulfilled credit so no notification can
appear; true retains the exact listener/resource/generation/child receipt and
the same closed Flow until its matching late notification is consumed without
ingress. Those metadata slots count against `max_sockets`, and no-incoming
credits do not accumulate tombstones. Physical confirmation is orthogonal.

After an embedder actually cuts off/joins the entire captured local Driver
transport callback session (possibly transferring pure remote receipts into
its surviving broker), `LocalCloseUnconfirmed` can finish local ownership. A
single socket close or bare WebSocket-close request is insufficient. The event
validates the exact admitted close request/resource and uses the existing
disconnect path to retire local callbacks/queued notifications; it reports
unconfirmed remote cleanup rather than waiting forever for a foreign server.
The embedder must ensure there can be no further producer into this old local
session. It cannot close a sibling run's session or fabricate a physical ACK.
Driver failure likewise retires local ownership without asserting remote join.
Resources retain their immutable existing driver generation, so old retained
wrappers/reports cannot close a replacement generation. A failed old wire close
keeps its original errno even if later cleanup of the newly known resource
succeeds or the eventual local session cutoff reports a different error.
Default unqualified Classic Close and default publication::Binding are unchanged.

Selected callback transports reserve one of their existing 64 RPC slots for
cutoff/close dispatch (ordinary calls admit at most 63). Dispatch releases that
RPC slot after the surviving owner has retained the close job; its eventual
physical result arrives separately as ProviderCloseAck. `revoke_open` cancels
only a captured socket's unfinished factory subscriptions, retaining late
cleanup. The Driver moves an unaccepted cached command into its existing
cleanup queue while selected close commands use that reserved capacity; an
already accepted command is never moved or replayed. Pending actual-address
queries preserve their identity and are withdrawn at their own close fence.

`poll_recv_close` optionally extracts only ProviderCloseAck/LocalCloseUnconfirmed from the same bounded
event queue while a different guest's RX is full. It must also drive completed
close-dispatch calls, and must leave payload/EOF order intact. Callback adapters
reserve one of the existing event slots for these acknowledgments and retain
proper wake registrations for every waiting producer. The default Classic
adapter does not implement this optional extraction. These requirements are
integration contracts, not proof that a stock remote relay supports them.

These source contracts and native in-memory tests do not establish browser,
Node or WISP acceptance. Selected UDP ingress and asynchronously acknowledged
host TCP option changes remain separate integration work; they must not be
advertised merely because a transport supports selected streams.

The stock v1 relay declares `Closed` but currently does not send it for TCP EOF
(`server.rs:RemoteAdapterSocket::drain_reads_and_accepts`, `Ok(0)` branch). Its
wire format cannot distinguish FIN from a peer reset. Consequently its default
`eof` capability is false. The backend model handles FIN/reset correctly when a
relay/provider supplies them; full stock-relay half-close/reset parity requires
relay-side work. Do not advertise that parity from the native model alone.

Classic resolution returns addresses only: the driver uses the question as the
canonical name and a 30-second synthesized TTL. Requests use absolute names to
avoid the relay host's search list. Reverse and raw-forward DNS require a separate
resolver-capable provider; unsupported lookups fail promptly. The stock UDP relay
also drops host send errors, cannot connect its UDP socket for asynchronous ICMP
errors, and drops empty inbound UDP datagrams. The backend supports empty inbound
messages when supplied, but the stock relay needs fixes for those cases.

Classic TCP publication supports fixed addresses, accept credits and asynchronous
bind-error reporting through `take_publication_error`. It has no synchronous
port-zero address reply or configurable native listen-backlog record. The explicit
asynchronous provider API resolves port zero with GetAddrLocal before publishing
its handle; guest backlog enforcement remains in the sink. Default-profile UDP
publication and urgent data are unsupported. Socket options with no
implemented wire effect return EOPNOTSUPP. These are explicit provider limits,
not changes to guest Linux socket policy.

B2 must implement and browser-test a bounded worker-local WebSocket/provider
transport and cross-worker wakers. B8 owns facade/network injection. Real browser
worker, endpoint-replacement and WISP-provider integration tests remain with that
integration. Nothing here implements or depends on C1 or C2.

## Opt-in fidelity provider

`Capabilities::classic_fidelity(ipv6)` selects our additive versioned protocol:
FIN versus reset, UDP host-send errors, PTR/raw DNS, urgent byte marks and fixed
UDP publication. Use it only with a matching provider. The stock profile is
unchanged; asynchronous publication resolves port zero through existing classic
records. See
[RELAY-FIDELITY.md](RELAY-FIDELITY.md) for the byte contract, deterministic test
provider, Linux authorities, exact stock-server changes and remaining limits.

### Resolved publications and UDP ICMP

Use `WebBackend::publish_resolved` / `publish_datagram_resolved` when the host
address requests port zero. They await the existing classic GetAddrLocal reply
before returning a publication. Keep polling the independent I/O driver; dropping
the future cancels its provisional publication. `Net::inbound_sink` supplies the
TCP destination and `Net::publish_udp_endpoint` adopts a resolved UDP pair.
Synchronous `Backend` publication still rejects port zero.

Fidelity providers can send destination-qualified `Event::DatagramRefused` for
actual ICMP port unreachable. It matches the current connected peer, reports
ECONNREFUSED once on the next send/recv, and supports bounded RECVERR quotes.
Local `DatagramError` remains separate. See RELAY-FIDELITY.md for exact stock
server/provider and WISP follow-ups; no production relay deployment is changed.

## Configured provider controls

`Capabilities::provider = Some(Readback { ... })` explicitly enables classic bridge,
unbridge, DHCP, address/MAC and route controls on the **same** relay session that
carries socket traffic. The default profiles leave this capability absent. The
records are the original classic interface records, with `Some(req_id)` selecting
the original server's supported success/error response even for mutations that
its old client submitted without waiting. No new relay wire extension is used.

Controls are bounded by `Config::max_lookups`. The driver serializes each entire
operation, its advertised readbacks, and namespace publication before starting
the next control. A caller dropping its wait does not cancel or replay an accepted
mutation: the driver retains its completion and publishes its result exactly once.
The callback runs outside backend locks. Driver loss fails queued calls and marks
an acknowledged mutation whose readback was incomplete as unreconciled.

`Readback` promises only getters the configured provider actually supports. No
incidental getter is required: a DHCP-only provider can return the original bare
address vector without inventing CIDR prefixes. Promised addresses/MAC/routes are
published together under the namespace's existing configuration lock, using an
uplink in `NetConfig`. A failed promised readback after remote success reports its
errno as a **partial commit**, retains `Completion::reconciliation`, and takes that
uplink down so old routing is unavailable. It does not roll back the remote side.
A later successful transaction repeats every promised getter and atomically
restores availability (unless the provider was explicitly unbridged). Unpromised
fields are unchanged; embedders must advertise the readbacks needed to reflect
that provider's configuration in the local namespace.

A malformed reply to a sent mutation is also a reconciliation failure. A sent
bridge/unbridge without a trustworthy ACK additionally makes bridge activity
unknown, including after transport reconnect. Successful address/MAC/route getters
can refresh configuration but cannot prove that activity. The uplink remains down
until a later explicit bridge/unbridge receives its proper ACK; an unbridge ACK
keeps it down. Known-ACK mutations with a subsequent failed getter remain eligible
for ordinary full-readback recovery.

Provider ioctl waits use the kernel's interruptible wait queue. A signal returns
`EINTR`, allowing fatal signals and shutdown to end an actually blocked guest.
The accepted operation is never automatically restarted, and removing the waiter
unregisters its guest waker while its provider-owned completion still publishes.

Route deadlines remain exact optional `u64` nanosecond values on the v1 surface
and original `Duration` records on the wire. Their interpretation and expiration
belong to the configured provider. WLK does not invent a clock or expire projected
routes independently of the external transport. Configured v1 lists and all
mutations use that provider; an operation's `EOPNOTSUPP` never selects a different
local route table. Without a provider the v1 adapter keeps its Linux netlink path
and explicitly rejects route deadlines that path cannot represent.

The private AF_NETLINK/NETLINK_ROUTE ioctl envelope in `vnet::provider` pins each
call to its socket's namespace. Mutations check the caller's and socket opener's
`CAP_NET_ADMIN` over that namespace before looking up the capability; read-only
queries have the same access policy as ordinary route/address dumps. These Rust
controls and native original-relay tests do not establish browser worker/endpoint
validation or any guarantee about a remote provider's own expiry policy.
