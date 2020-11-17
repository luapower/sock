
--secure sockets with libtls.
--Written by Cosmin Apreutesei. Public Domain.

local tls = require'libtls'
local ffi = require'ffi'
local C = tls.C

local stcp = {type = 'libtls_socket2_tcp_socket'}
local M = {stcp = stcp}

local cb_r_buf, cb_r_sz
local cb_w_buf, cb_w_sz

local read_cb = ffi.cast('tls_read_cb', function(self, buf, sz)
	sz = tonumber(sz)
	if cb_r_buf == buf then
		assert(cb_r_sz == sz)
		cb_r_buf, cb_r_sz = nil
		return sz
	else
		cb_r_buf = buf
		cb_r_sz  = sz
		return C.TLS_WANT_POLLIN
	end
end)

local write_cb = ffi.cast('tls_write_cb', function(self, buf, sz)
	sz = tonumber(sz)
	if cb_w_buf == buf then
		assert(cb_w_sz == sz)
		cb_w_buf, cb_w_sz = nil
		return sz
	else
		cb_w_buf = buf
		cb_w_sz  = sz
		return C.TLS_WANT_POLLOUT
	end
end)

function M.new(tcp, opt)
	local client = assert(opt.mode) == 'client'
	local tls, err = (client and tls.client or tls.server)(opt)
	if not tls then
		return nil, err
	end
	local ok, err
	if client then
		ok, err = tls:connect(vhost, read_cb, write_cb)
	else
		--TODO
		ok, err = tls:accept(cctx, read_cb, write_cb)
	end
	if not ok then
		tls:free()
		return nil, err
	end
	local stcp = {
		tcp = tcp,
		tls = tls,
		__index = M.stcp,
	}
	return setmetatable(stcp, stcp)
end

local function checkio(self, tls_ret, tls_err, tls_errcode)
	local recv = tls_err == 'wantrecv'
	local send = tls_err == 'wantsend'
	local send_or_recv =
		   (recv and self.tcp.recv)
		or (send and self.tcp.send)
	if not send_or_recv then
		return tls_ret, tls_err, tls_errcode
	end
	local buf = recv and cb_r_buf or cb_w_buf
	local sz  = recv and cb_r_sz  or cb_w_sz
	while sz > 0 do
		local tcp_len, tcp_err, tcp_errcode = send_or_recv(self.tcp, buf, sz)
		if not tcp_len then
			return tcp_len, tcp_err, tcp_errcode
		end
		buf = buf + tcp_len
		sz  = sz  - tcp_len
	end
	return 'retry'
end

function stcp:recv(buf, sz)
	cb_r_buf, cb_r_sz = nil
	cb_w_buf, cb_w_sz = nil
	local len, err, errcode
	repeat
		len, err, errcode = checkio(self, self.tls:recv(buf, sz))
	until len ~= 'retry'
	return len, err, errcode
end

function stcp:send(buf, sz)
	cb_r_buf, cb_r_sz = nil
	cb_w_buf, cb_w_sz = nil
	local len, err, errcode
	repeat
		len, err, errcode = checkio(self, self.tls:send(buf, sz))
	until len ~= 'retry'
	return len, err, errcode
end

function stcp:close()
	print('CLOSING')
	local ret, err = self.tls:close()
	self.tcp:close()
	self.tls:free()
	self.tls = nil
	self.tcp = nil
	return ret, err
end

return M
