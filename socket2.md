
## `local socket = require'socket2'`

Portable coroutine-based async socket API. For scheduling it uses IOCP
on Windows, epoll on Linux and kqueue on OSX.

## API

------------------------------------------------- ----------------------------
`socket.addr(ai_args...) -> ai`                   look-up a hostname
`ai:free()`                                       free the address list
`ai:next() -> ai`                                 get next address in list
`ai:addresses() -> iter() -> ai`                  iterate addresses
`ai.socket_type -> s`                             'udp' or 'tcp'
`ai.address_family -> s`                          'inet', 'inet6' or 'unix'
`ai.protocol -> s`                                'ip'
`ai.name -> s`                                    cannonical name
`ai.address -> s`                                 formatted address
`socket.tcp(['inet'|'inet6'], ['ip']) -> tcp`     make a TCP socket
`socket.udp(['inet'|'inet6'], ['ip']) -> udp`     make a UDP socket
`s:close()`                                       close connection and free socket
`s:bind(ai_args...)`                              bind socket to IP/port
`tcp:listen([backlog])`                           put socket in listening mode
`tcp:connect(ai_args...)`                         connect
`tcp:send(buf, maxlen) -> len`                    send bytes
`tcp:recv(buf, maxlen) -> len`                    receive bytes
`udp:send(buf, maxlen, ai_args...) -> len`        send a datagram to an address
`udp:recv(buf, maxlen, ai_args...) -> len`        receive a datagram from an adress
------------------------------------------------- ----------------------------

All function return `nil, err, errcode` on error.

I/O functions only work inside threads created with `socket.newthread()`.

## Address lookup

### `socket.addr(ai_args...) -> ai`

  * ai_args: `ai | [host], [port|service], ['tcp'|'udp'], ['inet'|'inet6'|'unix'], ['ip'], [flags]`

## Sockets

### `socket.tcp(['inet'|'inet6'|'unix'], ['ip']) -> tcp`

Make a TCP socket.

### `socket.udp(['inet'|'inet6'|'unix'], ['ip']) -> udp`

Make an UDP socket.

### `s:close()`

Close the connection and free the socket.

### `s:bind(ai_args...) -> true`

Bind socket to an ip/port.

### `tcp:listen(ai_args...) -> true`

Put the socket in listening mode.

### `tcp:connect(ai_args...) -> true`

Connect to an address.

### `tcp:send(buf, maxlen) -> len`

Send bytes.

### `tcp:recv(buf, maxlen) -> len`

Receive bytes.

### `udp:send(buf, maxlen, ai_args...) -> len`

Send a datagram.

### `udp:recv(buf, maxlen, ai_args...) -> len`

Receive a datagram.

## Socket loop

### `socket.poll(timeout) -> true | false,'timeout' | nil,err,errcode`

Poll for the next I/O event and resume the coroutine that waits for it.

### `loop.start(timeout) -> true | nil,err,errcode`

Start polling. Stops after the timeout expires and there's no more I/O
or `stop()` was called.

### `loop.stop()`

Tell the loop to stop dequeuing and return.

