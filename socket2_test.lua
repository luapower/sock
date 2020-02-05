
local thread = require'thread'
local socket = require'socket2'
local ffi = require'ffi'

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

		local s = assert(socket.new('tcp'))
		socket.loop.wrap(s)
		--s:setblocking(true)
		--assert(s:bind('127.0.0.1', 800))
		print('connect', s:connect('127.0.0.1', 80))
		print('send', s:send'GET / HTTP/1.0\r\n\r\n')
		local buf = ffi.new'char[4096]'
		local n, err = s:recv(buf, 4096)
		print('recv', n, n and ffi.string(buf, n) or err)
		s:close()

	end)

	print(socket.loop.start(1))

end

test_http()
