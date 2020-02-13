
## `local socket = require'socket2'`

Portable coroutine-based async socket API. For scheduling it uses IOCP
on Windows, epoll on Linux and kqueue on OSX.

## API

------------------------------------------------- ----------------------------
__address lookup__
`socket.addr(ai_args...) -> ai`                   look-up a hostname
`ai:free()`                                       free the address list
`ai:next() -> ai|nil`                             get next address in list
`ai:addresses() -> iter() -> ai`                  iterate addresses
`ai.socket_type -> s`                             'udp' or 'tcp'
`ai.family -> s`                                  'inet', 'inet6' or 'unix'
`ai.protocol -> s`                                'ip'
`ai.name -> s`                                    cannonical name
`ai.addr:tostring() -> s`                         formatted address
__sockets__
`socket.tcp(['inet'|'inet6'], ['ip']) -> tcp`     make a TCP socket
`socket.udp(['inet'|'inet6'], ['ip']) -> udp`     make a UDP socket
`s:close()`                                       close connection and free socket
`s:bind(ai_args...)`                              bind socket to IP/port
__TCP sockets__
`tcp:listen([backlog])`                           put socket in listening mode
`tcp:connect(ai_args...)`                         connect
`tcp:send(buf, maxlen) -> len`                    send bytes
`tcp:recv(buf, maxlen) -> len`                    receive bytes
__UDP sockets__
`udp:send(buf, maxlen, ai_args...) -> len`        send a datagram to an address
`udp:recv(buf, maxlen, ai_args...) -> len`        receive a datagram from an adress
__polling__
`socket.poll(timeout) -> true | false,'timeout'`  poll for I/O
`socket.start(timeout) -> true`                   keep polling until timeout
`socket.stop()`                                   stop polling
__threading__
`socket.iocp([iocp_h]) -> iocp_h`                 get/set IOCP handle (Windows)
`socket.epoll_fd([epfd]) -> epfd`                 get/set epoll fd (Linux)
------------------------------------------------- ----------------------------

All function return `nil, err, errcode` on error.

I/O functions only work inside threads created with `socket.newthread()`.

## Address lookup

### `socket.addr(ai_args...) -> ai`

`ai_args` cam be either:

  * `[host], [port|service], ['tcp'|'udp'], ['inet'|'inet6'|'unix'], ['ip'], [flags]`
  * or an existing `ai` object.

## Sockets

### `socket.tcp(['inet'|'inet6'|'unix'], ['ip']) -> tcp`

Make a TCP socket.

### `socket.udp(['inet'|'inet6'|'unix'], ['ip']) -> udp`

Make an UDP socket.

### `s:close()`

Close the connection and free the socket.

### `s:bind(ai_args...) -> true`

Bind socket to an ip/port.

## TCP sockets

### `tcp:listen(ai_args...) -> true`

Put the socket in listening mode.

### `tcp:connect(ai_args...) -> true`

Connect to an address.

### `tcp:send(buf, maxlen) -> len`

Send bytes.

### `tcp:recv(buf, maxlen) -> len`

Receive bytes.

## UDP sockets

### `udp:send(buf, maxlen, ai_args...) -> len`

Send a datagram.

### `udp:recv(buf, maxlen, ai_args...) -> len`

Receive a datagram.

## Polling

### `socket.poll(timeout) -> true | false,'timeout' | nil,err,errcode`

Poll for the next I/O event and resume the coroutine that waits for it.

### `socket.start(timeout) -> true | nil,err,errcode`

Start polling. Stops after the timeout expires and there's no more I/O
or `stop()` was called.

### `socket.stop()`

Tell the loop to stop dequeuing and return.

## Threading

### `socket.iocp([iocp_handle]) -> iocp_handle`

Get/set the global IOCP handle (Windows).

IOCPs can be shared between threads and having a single IOCP for all
threads is more efficient for the kernel than having one IOCP per thread.
To share the IOCP with another Lua state running on a different thread,
get the IOCP handle with `socket.iocp()`, copy it over to the other state,
then set it with `socket.iocp(copied_iocp)`.

### `socket.epoll_fd([epfd]) -> epfd`

Get/set the global epoll fd (Linux).

Epoll fds can be shared between threads and having a single epfd for all
threads is more efficient for the kernel than having one epfd per thread.
To share the epfd with another Lua state running on a different thread,
get the epfd with `socket.epoll_fd()`, copy it over to the other state,
then set it with `socket.epoll_fd(copied_epfd)`.

