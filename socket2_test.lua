
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
		s:close()
	end)

	local s = assert(socket.socket'tcp')

	--assert(s:bind('127.0.0.1', 8090))
	s:setblocking(false)
	print(s:connect('127.0.0.1', '8080'))
	--assert(s:send'hello')
	s:close()

	server_thread:join()
end

local function test_http()

	socket.loop.newthread(function()

		local s = assert(socket.tcp())
		--s:setblocking(true)
		--assert(s:bind('127.0.0.1', 800))
		print('connect', s:connect('127.0.0.1', 80))
		print('send', s:send'GET / HTTP/1.0\r\n\r\n')
		local buf = ffi.new'char[4096]'
		local n, err = s:recv(buf, 4096)
		print('recv', n, n and ffi.string(buf, n) or err)
		s:close()

	end)

	print(socket.start(1))

end

test_addr()
test_http()
