
--(secure) sockets for http client and server protocols based on socket2, libtls.
--Written by Cosmin Apreutesei. Public Domain.

local socket = require'socket2'

local M = {}

M.tcp       = socket.tcp
M.suspend   = socket.suspend
M.resume    = socket.resume
M.thread    = socket.thread
M.newthread = socket.newthread
M.start     = socket.start

--http<->socket2 binding -----------------------------------------------------

function M.http_bind_socket(http, sock)

	function http:getsocket() return sock end
	function http:setsocket(newsock) sock = newsock end

	function http:read(buf, sz)
		return sock:recv(buf, sz)
	end

	function http:send(buf, sz)
		return sock:send(buf, sz)
	end

	function http:close()
		sock:close()
		self.closed = true
	end

end

--http<->libtls binding ------------------------------------------------------

local function load_file(self, kf, ks, t1, t0)
	local t = t1[kf] and t1 or t0
	t[ks] = t[ks] or assert(glue.readfile(t[kf]))
end

function M.http_bind_tls(self, http, tcp, vhost, mode, tls_options, class_tls_options)

	local stcp = require'socket2_libtls'

	assert(mode == 'client' or mode == 'server')
	if mode == 'client' then
		load_file(self, 'ca_file', 'ca', tls_options, class_tls_options)
	end
	local opt = glue.update({}, class_tls_options, tls_options)
	local stcp, err = stcp.new(tcp, {
		mode = mode,
		ca = opt.ca,
		servername = vhost,
		insecure_noverifycert = opt.insecure_noverifycert,
	})
	if not stcp then
		self:close()
		return nil, err
	end
	http:setsocket(stcp)
	return true
end


return M
