
## `local sock = require'sock'`

Portable coroutine-based async socket API. For scheduling it uses IOCP
on Windows, epoll on Linux and kqueue on OSX.

## Rationale

Replace LuaSocket which doesn't scale being select()-based, and improve on
other aspects too (single file, nothing to compile, use cdata buffers instead
of strings, don't bundle unrelated modules, [coro]-based async only,
multi-threading support).

## Status

<warn>Alpha (Windows & Linux)</warn>

## API

---------------------------------------------------------------- ----------------------------
__address lookup__
`socket.addr(...) -> ai`                                         look-up a hostname
`ai:free()`                                                      free the address list
`ai:next() -> ai|nil`                                            get next address in list
`ai:addrs() -> iter() -> ai`                                     iterate addresses
`ai:type() -> s`                                                 socket type: 'tcp', ...
`ai:family() -> s`                                               address family: 'inet', ...
`ai:protocol() -> s`                                             protocol: 'tcp', 'icmp', ...
`ai:name() -> s`                                                 cannonical name
`ai:tostring() -> s`                                             formatted address
__sockets__
`socket.tcp([family][, protocol]) -> tcp`                        make a TCP socket
`socket.udp([family][, protocol]) -> udp`                        make a UDP socket
`socket.raw([family][, protocol]) -> raw`                        make a RAW socket
`s:type() -> s`                                                  socket type
`s:family() -> s`                                                address family
`s:protocol() -> s`                                              protocol
`s:close()`                                                      send FIN and/or RST and free socket
`s:bind(addr | host,port, [addr_flags])`                         bind socket to IP/port
`s:setopt(opt, val)`                                             set socket option (`so_*` or `tcp_*`)
`s:getopt(opt) -> val`                                           get socket option
__TCP sockets__
`tcp:listen([backlog, ]addr | host,port, [addr_flags])`          put socket in listening mode
`tcp:connect(addr | host,port, [expires])`                       connect
`tcp:accept([expires]) -> ctcp, remote_addr, local_addr`         accept a connection
`tcp:send(s|buf, [maxlen], [expires]) -> len`                    send bytes
`tcp:recv(buf, maxlen, [expires]) -> len`                        receive bytes
`tcp:shutdown('r'|'w'|'rw', [expires])`                          send FIN
__UDP sockets__
`udp:send(s|buf, [maxlen], addr | host,port, [expires]) -> len`  send a datagram to an address
`udp:recv(buf, maxlen, addr | host,port, [expires]) -> len`      receive a datagram from an adress
__scheduling__
`socket.newthread(func) -> co`                                   create a coroutine for async I/O
`socket.poll()`                                                  poll for I/O
`socket.start()`                                                 keep polling until all threads finish
`socket.stop()`                                                  stop polling
`socket.sleep_until(t)`                                          sleep without blocking until time.clock() value
`socket.sleep(s)`                                                sleep without blocking for s seconds
__multi-threading__
`socket.iocp([iocp_h]) -> iocp_h`                                get/set IOCP handle (Windows)
`socket.epoll_fd([epfd]) -> epfd`                                get/set epoll fd (Linux)
---------------------------------------------------------------- ----------------------------

All function return `nil, err, errcode` on error. Some error messages
are normalized across platforms, like 'access_denied' and 'address_already_in_use'
so they can be used as conditionals.

I/O functions only work inside threads created with `socket.newthread()`.

The optional `expires` arg controls the timeout of the operation and must be
a time.clock() value. If the expiration clock is reached before the operation
completes the socket is forcibly closed and `nil, 'timeout'` is returned.

## Address lookup

### `socket.addr(...) -> ai`

The args can be either an existing `ai` object which is passed through, or:

  * `[host], [port], socket_type, [family], [protocol], [flags]`

where

  * `host` can be a hostname, ip address, `'*'` (the default) which means
  `'0.0.0.0'` aka "all interfaces" or `false` which means `'127.0.0.1'`.
  * `port` can be a port number or a service name and defaults to `0`
  which means "any available port".
  * `socket_type` must be `'tcp'`, `'udp'` or `'raw'`.
  * `family` can be `'inet'`, `'inet6'` or `'unix'` (defaults to `'inet'`).
  * `protocol` can be `'ip'`, `'ipv6'`, `'tcp'`, `'udp'`, `'raw'`, `'icmp'`,
  `'igmp'` or `'icmpv6'` (default is based on socket type).
  * flags are a [glue.bor()][glue] list of `passive`, `cannonname`,
    `numerichost`, `numericserv`, `all`, `v4mapped`, `addrconfig`
    which map to `getaddrinfo()` flags.

## Sockets

### `socket.tcp([family][, protocol]) -> tcp`

Make a TCP socket.

### `socket.udp([family][, protocol]) -> udp`

Make an UDP socket.

### `socket.raw([family][, protocol]) -> raw`

Make a RAW socket.

### `s:close()`

Close the connection and free the socket.

For TCP sockets, if 1) there's unread incoming data (i.e. recv() hasn't
returned 0 yet), or 2) `so_linger` socket option was set with a zero timeout,
then a TCP RST packet is sent to the client, otherwise a FIN is sent.

### `s:bind(addr | [host],[port])`

Bind socket to an interface/port.

## TCP sockets

### `tcp:listen([backlog, ]addr | [host],[port])`

Put the socket in listening mode, binding the socket if not bound already
(in which case `host` and `port` args are ignored). The `backlog` defaults
to `1/0` which means "use the maximum allowed".

### `tcp:connect(addr | host,port, [expires])`

Connect to an address, binding the socket to `'*'` if not bound already.

### `tcp:accept([expires]) -> ctcp, remote_addr, local_addr`

Accept a connection.

### `tcp:send(s|buf, [maxlen], [expires]) -> len`

Send bytes.

### `tcp:recv(buf, maxlen, [expires]) -> len`

Receive bytes.

## UDP sockets

### `udp:send(s|buf, [maxlen], addr | host,port, [expires]) -> len`

Send a datagram.

### `udp:recv(buf, maxlen, addr | host,port, [expires]) -> len`

Receive a datagram.

### `tcp:shutdown('r'|'w'|'rw')`

Shutdown the socket for receiving, sending or both. Does not block.

Sends a TCP FIN packet to indicate refusal to send/receive any more data
on the connection. The FIN packet is only sent after all the current pending
data is sent (unlike RST which is sent immediately). When a FIN is received
recv() returns `nil,'closed'`.

Calling close() without shutdown may send a RST (see the notes on `close()`
for when that can happen) which may cause any data that is pending either
on the sender side or on the receiving side to be discarded (that's how TCP
works: RST has that data-cutting effect).

Required for lame protocols like HTTP with pipelining: a HTTP server
that wants to close the connection before honoring all the received
pipelined requests needs to call `s:shutdown'w'` (which sends a FIN to
the client) and then continue to receive (and discard) everything until
a `nil,'closed'` recv comes in (which is a FIN from the client, as a reply
to the FIN from the server) and only then it can close the connection without
messing up the client.

## Scheduling

Scheduling is based on synchronous coroutines provided by [coro] which
allows coroutine-based iterators that perform socket I/O to be written.

### `socket.newthread(func) -> co`

Create a coroutine for performing async I/O. The coroutine starts immediately
and transfers control back to the _parent thread_ inside the first async
I/O operation. When the coroutine finishes, the control is transfered to
the loop thread.

Full-duplex I/O on a socket can be achieved by performing reads in one thread
and all writes in another.

### `socket.poll(timeout) -> true | false,'timeout'`

Poll for the next I/O event and resume the coroutine that waits for it.

Timeout is in seconds with anything beyond 2^31-1 taken as infinte
and defaults to infinite.

### `socket.start(timeout)`

Start polling. Stops after the timeout expires and there's no more I/O
or `stop()` was called.

### `socket.stop()`

Tell the loop to stop dequeuing and return.

### `socket.sleep_until(t)`

Sleep until a time.clock() value without blocking other threads.

### `socket.sleep(s)`

Sleep `s` seconds without blocking other threads.

## Multi-threading

### `socket.iocp([iocp_handle]) -> iocp_handle`

Get/set the global IOCP handle (Windows).

IOCPs can be shared between OS threads and having a single IOCP for all
threads (as opposed to having one IOCP per thread/Lua state) enables the
kernel to better distribute the completion events between threads.

To share the IOCP with another Lua state running on a different thread,
get the IOCP handle with `socket.iocp()`, copy it over to the other state,
then set it with `socket.iocp(copied_iocp)`.

### `socket.epoll_fd([epfd]) -> epfd`

Get/set the global epoll fd (Linux).

Epoll fds can be shared between OS threads and having a single epfd for all
threads is more efficient for the kernel than having one epfd per thread.

To share the epfd with another Lua state running on a different thread,
get the epfd with `socket.epoll_fd()`, copy it over to the other state,
then set it with `socket.epoll_fd(copied_epfd)`.
