
## `local s2tls = require'socket2_libtls'`

Secure async sockets with [socket2] and [libtls].

## API

----------------------------------------------------- -----------------------------------
`s2tls.client_stcp(tcp, servername, opt) -> cstcp`    create a secure socket for a client
`s2tls.server_stcp(tcp, opt) -> sstcp`                create a secure socket for a server
`cstcp:recv()`                                        same semantics as `tcp:recv()`
`cstcp:send()`                                        same semantics as `tcp:send()`
`sstcp:accept() -> cstcp`                             accept a client connection
`cstcp:shutdown('r'|'w'|'rw')`                        calls `self.tcp:shutdown()`
`cstcp:close()`                                       close client socket
`sstcp:close()`                                       close server socket
----------------------------------------------------- -----------------------------------
