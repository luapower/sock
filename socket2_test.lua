
local thread = require'thread'
local socket = require'socket2'
local ffi = require'ffi'

local function test_addr()
	local function dump(...)
		for ai in assert(socket.addr(...)):addresses() do
			print(ai:address(), ai:socket_type(), ai:address_family(), ai:protocol(), ai:name())
		end
	end
	dump('1234:2345:3456:4567:5678:6789:7890:8901', 0, 'tcp', 'inet6')
	dump('123.124.125.126', 0, 'tcp', 'inet', nil, {cannonname = true})
	dump(nil, 0, nil, nil, nil, {all = true})

end

local function start_server()
	local server_thread = thread.new(function()
		local socket = require'socket2'
		local s = assert(socket.new'tcp')
		assert(s:bind('127.0.0.1', 8090))
		assert(s:listen())
		while true do
			local cs = assert(s:accept())
			local thread = socket.newthread(function()

			end)
		end
		s:close()
	end)

	local s = assert(socket.socket'tcp')

	--assert(s:bind('127.0.0.1', 8090))
	print(s:connect('127.0.0.1', '8080'))
	--assert(s:send'hello')
	s:close()

	server_thread:join()
end

local function test_http()

	socket.newthread(function()

		local s = assert(socket.tcp())
		--s:setblocking(true)
		--assert(s:bind('127.0.0.1', 800))
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

start_server()

--test_addr()
--test_http()
