
## `local socket = require'socket2'`

Portable coroutine-based async socket API. For scheduling it uses IOCP
on Windows, epoll on Linux and kqueue on OSX.

## API

## Address lookup

### `socket.addr(ai_args...) -> ai`

  * ai_args: `ai | [host], [port], ['tcp'|'udp'], ['inet'|'inet6'], ['ip'], [flags]`

## Sockets

### `socket.tcp(['inet'|'inet6'], ['ip']) -> tcp | nil,err,errcode`

### `socket.udp(['inet'|'inet6'], ['ip']) -> udp | nil,err,errcode`

### `s:bind(ai_args...) -> true | nil,err,errcode`

### `tcp:connect(ai_args...) -> true | nil,err,errcode`

### `tcp:send(buf, maxlen) -> len | nil,err,errcode`

### `tcp:recv(buf, maxlen) -> len | nil,err,errcode`

### `udp:send(buf, maxlen, ai_args...) -> len | nil,err,errcode`

### `udp:recv(buf, maxlen, ai_args...) -> len | nil,err,errcode`

## Socket loop

### `socket.poll(timeout) -> true | false,'timeout' | nil,err,errcode`

Poll for the next I/O event and resume the coroutine that waits for it.

### `loop.start(timeout) -> true | nil,err,errcode`

Start polling. Stops after the timeout expires and there's no more I/O
or `stop()` was called.

### `loop.stop()`

Tell the loop to stop dequeuing and return.

