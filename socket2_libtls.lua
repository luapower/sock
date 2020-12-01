
if not ... then require'http_server_test'; return end

--secure sockets with libtls.
--Written by Cosmin Apreutesei. Public Domain.

require'socket2' --not used directly, but it is a dependency.
local tls = require'libtls'
local ffi = require'ffi'
local C = tls.C

local client_stcp = {type = 's2tls_tcp_client_socket'}
local server_stcp = {type = 's2tls_tcp_server_socket'}
local M = {}

local cb_r_buf, cb_r_sz, cb_r_len
local cb_w_buf, cb_w_sz, cb_w_len

local read_cb = ffi.cast('tls_read_cb', function(self, buf, sz)
	sz = tonumber(sz)
	--print('tls_read_cb', buf, sz, cb_r_buf)
	if cb_r_buf == nil then
		cb_r_buf = buf
		cb_r_sz  = sz
		return C.TLS_WANT_POLLIN
	else
		assert(cb_r_buf == buf)
		assert(cb_r_len <= sz)
		cb_r_buf = nil
		return cb_r_len
	end
end)

local write_cb = ffi.cast('tls_write_cb', function(self, buf, sz)
	sz = tonumber(sz)
	--print('tls_write_cb', buf, sz, cb_w_buf)
	if cb_w_buf == nil then
		cb_w_buf = buf
		cb_w_sz  = sz
		return C.TLS_WANT_POLLOUT
	else
		assert(cb_w_buf == buf)
		assert(cb_w_len <= sz)
		cb_w_buf = nil
		return cb_w_len
	end
end)

function M.client_stcp(tcp, servername, opt)
	local tls, err = tls.client(opt)
	if not tls then
		return nil, err
	end
	local ok, err = tls:connect(servername, read_cb, write_cb)
	if not ok then
		tls:free()
		return nil, err
	end
	local stcp = {
		tcp = tcp,
		tls = tls,
		__index = client_stcp,
	}
	return setmetatable(stcp, stcp)
end

function M.server_stcp(tcp, opt)
	local tls, err = tls.server(opt)
	if not tls then
		return nil, err
	end
	local stcp = {
		tcp = tcp,
		tls = tls,
		__index = server_stcp,
	}
	return setmetatable(stcp, stcp)
end

function server_stcp:accept()
	local ctcp, err, errcode = self.tcp:accept()
	if not ctcp then
		return nil, err, errcode
	end
	local ctls, err = self.tls:accept(read_cb, write_cb)
	if not ctls then
		return nil, err
	end
	local stcp = {
		tcp = ctcp,
		tls = ctls,
		__index = client_stcp,
	}
	return setmetatable(stcp, stcp)
end

local function checkio(self, expires, tls_ret, tls_err)
	--print('checkio', tls_ret, tls_err)
	if tls_err == 'wantrecv' then
		local buf, sz = cb_r_buf, cb_r_sz
		--print('>recv', buf, sz)
		local len, err, errcode = self.tcp:recv(buf, sz, expires)
		--print('<recv', len, err, errcode)
		if not len then
			if err == 'closed' then
				len = 0
			else
				return false, len, err, errcode
			end
		end
		cb_r_buf, cb_r_sz, cb_r_len = buf, sz, len
		return true
	elseif tls_err == 'wantsend' then
		local buf, sz = cb_w_buf, cb_w_sz
		--print('>send', buf, sz)
		local len, err, errcode = self.tcp:send(buf, sz, expires)
		--print('<send', len, err, errcode)
		if not len then
			if err == 'closed' then
				len = 0
			else
				return false, len, err, errcode
			end
		end
		cb_w_buf, cb_w_sz, cb_w_len = buf, sz, len
		return true
	elseif tls_ret == 0 then
		return false, nil, 'closed'
	else
		return false, tls_ret, tls_err
	end
end

function client_stcp:recv(buf, sz, expires)
	cb_r_buf = nil
	cb_w_buf = nil
	while true do
		local recall, ret, err, errcode = checkio(self, expires, self.tls:recv(buf, sz))
		if not recall then return ret, err, errcode end
	end
end

function client_stcp:send(buf, sz, expires)
	cb_r_buf = nil
	cb_w_buf = nil
	while true do
		local recall, ret, err, errcode = checkio(self, expires, self.tls:send(buf, sz))
		if not recall then return ret, err, errcode end
	end
end

function client_stcp:shutdown(mode)
	return self.tcp:shutdown(mode)
end

function client_stcp:close(expires)
	if self.closed then return true end
	cb_r_buf = nil
	cb_w_buf = nil
	while true do
		local recall, ret, err, errcode = checkio(self, expires, self.tls:close())
		if not recall then return ret, err, errcode end
	end
	self.tcp:close()
	self.tls:free()
	self.tls = nil
	self.tcp = nil
	self.closed = true
	return true
end

server_stcp.close = client_stcp.close

M.config = tls.config

return M
