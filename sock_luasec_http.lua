
--secure sockets for http client and server protocols based on socketloop, luasocket, luasec.
--Written by Cosmin Apreutesei. Public Domain.

local loop = require'socketloop'
local ffi = require'ffi'

local M = {}

M.tcp       = loop.tcp
M.suspend   = loop.suspend
M.resume    = loop.resume
M.thread    = loop.current
M.newthread = loop.newthread
M.start     = loop.start

--http<->luasocket binding ---------------------------------------------------

function M.http_bind_socket(http, sock)

	function http:getsocket() return sock end
	function http:setsocket(newsock) sock = newsock end

	function http:read(buf, sz)
		local s, err, p = sock:receive(sz, nil, true)
		if not s then return nil, err end
		assert(#s <= sz)
		ffi.copy(buf, s, #s)
		return #s
	end

	function http:send(buf, sz)
		sz = sz or #buf
		local s = ffi.string(buf, sz)
		return sock:send(s)
	end

	function http:close()
		sock:close()
		self.closed = true
	end

end

--http<->luasec binding ------------------------------------------------------

function M.http_bind_tls(self, http, sock, vhost, mode, tls_options, class_tls_options)

	local ssl = require'ssl'

	assert(mode == 'client' or mode == 'server')
	local opt = glue.update({}, class_tls_options, tls_options)
	local ssock = ssl.wrap(sock, {
		mode     = mode,
		protocol = 'any',
		options  = {'all', 'no_sslv2', 'no_sslv3', 'no_tlsv1'},
		verify   = opt.insecure_noverifycert and 'none' or 'peer',
		cafile   = opt.ca_file,
	})
	ssock:sni(vhost)
	sock:setsocket(ssock)
	local ok, err
	if sock.call_async then
		ok, err = sock:call_async(sock.dohandshake, sock)
	else
		while true do
			ok, err = ssock:dohandshake()
			if ok or (err ~= 'wantread' and err ~= 'wantwrite') then
				break
			end
		end
	end
	if not ok then
		self:close()
		return nil, err
	end
	return true
end


return M
