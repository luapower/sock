
io.stdout:setvbuf'no'
io.stderr:setvbuf'no'

local glue = require'glue'
local thread = require'thread'
local socket = require'socket2'
local ffi = require'ffi'
local coro = require'coro'

local function test_addr()
	local function dump(...)
		for ai in assert(socket.addr(...)):addrs() do
			print(ai:tostring(), ai:type(), ai:family(), ai:protocol(), ai:name())
		end
	end
	dump('1234:2345:3456:4567:5678:6789:7890:8901', 0, 'tcp', 'inet6')
	dump('123.124.125.126', 1234, 'tcp', 'inet', nil, {cannonname = true})
	dump()

end

local function test_sockopt()
	local s = assert(socket.tcp())
	for _,k in ipairs{
		'so_acceptconn        ',
		'so_broadcast         ',
		--'so_bsp_state       ',
		'so_conditional_accept',
		'so_connect_time      ',
		'so_dontlinger        ',
		'so_dontroute         ',
		'so_error             ',
		'so_exclusiveaddruse  ',
		'so_keepalive         ',
		--'so_linger          ',
		'so_max_msg_size      ',
		'so_maxdg             ',
		'so_maxpathdg         ',
		'so_oobinline         ',
		'so_pause_accept      ',
		'so_port_scalability  ',
		--'so_protocol_info   ',
		'so_randomize_port    ',
		'so_rcvbuf            ',
		'so_rcvlowat          ',
		'so_rcvtimeo          ',
		'so_reuseaddr         ',
		'so_sndbuf            ',
		'so_sndlowat          ',
		'so_sndtimeo          ',
		'so_type              ',
		'tcp_bsdurgent        ',
		'tcp_expedited_1122   ',
		'tcp_maxrt            ',
		'tcp_nodelay          ',
		'tcp_timestamps       ',
	} do
		local sk, k = k, glue.trim(k)
		local v = s:getopt(k)
		print(sk, v)
	end

	print''

	for _,k in ipairs{
		'so_broadcast              ',
		'so_conditional_accept     ',
		'so_dontlinger             ',
		'so_dontroute              ',
		'so_exclusiveaddruse       ',
		'so_keepalive              ',
		'so_linger                 ',
		'so_max_msg_size           ',
		'so_oobinline              ',
		'so_pause_accept           ',
		'so_port_scalability       ',
		'so_randomize_port         ',
		'so_rcvbuf                 ',
		'so_rcvlowat               ',
		'so_rcvtimeo               ',
		'so_reuseaddr              ',
		'so_sndbuf                 ',
		'so_sndlowat               ',
		'so_sndtimeo               ',
		'so_update_accept_context  ',
		'so_update_connect_context ',
		'tcp_bsdurgent             ',
		'tcp_expedited_1122  	   ',
		'tcp_maxrt           	   ',
		'tcp_nodelay               ',
		'tcp_timestamps      	   ',
	} do
		local sk, k = k, glue.trim(k)
		local canget, v = pcall(s.getopt, s, k)
		if canget then
			print(k, pcall(s.setopt, s, k, v))
		end
	end
end

local function start_server()
	local server_thread = thread.new(function()
		local socket = require'socket2'
		local coro = require'coro'
		local s = assert(socket.tcp())
		assert(s:listen('*', 8090))
		socket.newthread(function()
			while true do
				print'...'
				local cs, ra, la = assert(s:accept())
				print('accepted', cs, ra:tostring(), ra:port(), la and la:tostring(), la and la:port())
				print('accepted_thread', coro.running())
				socket.newthread(function()
					print'closing cs'
					--cs:recv(buf, len)
					assert(cs:close())
					print('closed', coro.running())
				end)
				print('backto accepted_thread', coro.running())
			end
			s:close()
		end)
		print(socket.start())
	end)

	-- local s = assert(socket.tcp())
	-- --assert(s:bind('127.0.0.1', 8090))
	-- print(s:connect('127.0.0.1', '8080'))
	-- --assert(s:send'hello')
	-- s:close()

	server_thread:join()
end

local function start_client()
	local s = assert(socket.tcp())
	socket.newthread(function()
		print'...'
		print(assert(s:connect(ffi.abi'win' and '10.8.1.130' or '10.8.2.153', 8090)))
		print(assert(s:send'hello'))
		print(assert(s:close()))
		socket.stop()
	end)
	print(socket.start())
end

local function test_http()

	socket.newthread(function()

		local s = assert(socket.tcp())
		print('connect', s:connect(ffi.abi'win' and '127.0.0.1' or '10.8.2.153', 80))
		print('send', s:send'GET / HTTP/1.0\r\n\r\n')
		local buf = ffi.new'char[4096]'
		local n, err, ec = s:recv(buf, 4096)
		if n then
			print('recv', n, ffi.string(buf, n))
		else
			print(n, err, ec)
		end
		s:close()

	end)

	print('start', socket.start(1))

end

--test_addr()
--test_sockopt()
--test_http()

if ffi.os == 'Windows' then
	start_server()
else
	start_client()
end

