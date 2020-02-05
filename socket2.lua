
--Portable socket API with IOCP and epoll for LuaJIT.
--Written by Cosmin Apreutesei. Public Domain.

if not ... then require'socket2_test'; return end

local ffi = require'ffi'
local bit = require'bit'

local glue = require'glue'
local coro = require'coro'

local Windows = ffi.abi'win'
local Linux = ffi.os == 'Linux'

local C = Windows and ffi.load'ws2_32' or ffi.C
local M = {C = C}
local socket = {}

local check --fw. decl.

ffi.cdef[[
typedef unsigned long u_long;
typedef uintptr_t SOCKET;
typedef struct sockaddr sockaddr;
]]

local INVALID_SOCKET = ffi.cast('SOCKET', -1)

local wrap_socket --fw. decl.

--sockaddr construction ------------------------------------------------------

ffi.cdef[[
struct in_addr {
	union {
		unsigned long s_addr;
		struct {
			uint8_t _1;
			uint8_t _2;
			uint8_t _3;
			uint8_t _4;
		};
	};
};
struct sockaddr_in {
	short          sin_family;
	unsigned short sin_port;
	struct in_addr sin_addr;
	char           sin_zero[8];
};

struct in6_addr {
	unsigned char s6_addr[16];
};
struct sockaddr_in6 {
	short           sin6_family;
	unsigned short  sin6_port;
	unsigned long   sin6_flowinfo;
	struct in6_addr sin6_addr;
	unsigned long   sin6_scope_id;
};
]]

if Windows then
	ffi.cdef[[
	struct addrinfo {
		int             ai_flags;
		int             ai_family;
		int             ai_socktype;
		int             ai_protocol;
		size_t          ai_addrlen;
		char            *ai_canonname;
		struct sockaddr *ai_addr;
		struct addrinfo *ai_next;
	};
	]]
else
	ffi.cdef[[
	struct addrinfo {
		int              ai_flags;
		int              ai_family;
		int              ai_socktype;
		int              ai_protocol;
		size_t           ai_addrlen;
		struct sockaddr *ai_addr;
		char            *ai_canonname;
		struct addrinfo *ai_next;
	};
	]]
end

ffi.cdef[[
int getaddrinfo(const char *node, const char *service,
	const struct addrinfo *hints,
	struct addrinfo **res);
void freeaddrinfo(struct addrinfo *);
]]

local socketargs
do
	local address_families = {
		inet = 2,
		inet6 = 23,
	}
	local address_family_map = glue.index(address_families)

	local socket_types = {
		tcp = 1,
		udp = 2,
	}
	local socket_type_map = glue.index(socket_types)

	local protocols = {
		ip = 0,
		icmp = 1,
		igmp = 2,
		tcp = 6,
		udp = 17,
		raw = 255,
	}
	local protocol_map = glue.index(protocols)

	local flag_bits = {
		passive     = Windows and 0x00000001 or 0x0001,
		cannonname  = Windows and 0x00000002 or 0x0002,
		numerichost = Windows and 0x00000004 or 0x0004,
		numericserv = Windows and 0x00000008 or 0x0400,
		all         = Windows and 0x00000100 or 0x0010,
		v4mapped    = Windows and 0x00000800 or 0x0008,
		addrconfig  = Windows and 0x00000400 or 0x0020,
	}

	function socketargs(socket_type, address_family, protocol)
		local st = socket_type and assert(socket_types[socket_type]) or 0
		local af = address_family and assert(address_families[address_family]) or 0
		local prot = protocol and assert(protocols[protocol]) or 0
		return st, af, prot
	end

	local hints = ffi.new'struct addrinfo'
	local addrs = ffi.new'struct addrinfo*[1]'
	local addrinfo_ct = ffi.typeof'struct addrinfo'

	function M.addr(host, port, socket_type, address_family, protocol, flags)
		if ffi.istype(addrinfo_ct, host) then
			return host, true --pass-through
		elseif type(host) == 'table' then
			local t = host
			host, port, address_family, socket_type, protocol, flags =
				t.host, t.port, t.address_family, t.socket_type, t.protocol, t.flags
		end
		ffi.fill(hints, ffi.sizeof(hints))
		hints.ai_socktype, hints.ai_family, hints.ai_protocol
			= socketargs(socket_type, address_family, protocol)
		hints.ai_flags = glue.bor(flags or 0, flag_bits, true)
		local ret = C.getaddrinfo(host, port and tostring(port), hints, addrs)
		if ret ~= 0 then return check() end
		return ffi.gc(addrs[0], C.freeaddrinfo)
	end

	local ai = {}

	function ai:free()
		ffi.gc(self, nil)
		C.freeaddrinfo(self)
	end

	function ai:next(ai)
		local ai = ai and ai.ai_next or self
		return ai ~= nil and ai or nil
	end

	function ai:addresses()
		return ai.next, self
	end

	function ai:socket_type()
		return socket_type_map[self.ai_socktype]
	end

	function ai:address_family()
		return address_family_map[self.ai_family]
	end

	function ai:protocol()
		return protocol_map[self.ai_protocol]
	end

	local function str(s, len)
		if s == nil then return nil end
		return ffi.string(s, len)
	end

	function ai:name()
		return str(self.ai_canonname)
	end

	function ai:address()
		local at = self:address_family()
		if at == 'inet' then
			local ip = ffi.cast('struct sockaddr_in*', self.ai_addr).sin_addr
			return string.format('%d.%d.%d.%d', ip._1, ip._2, ip._3, ip._4)
		elseif at == 'inet6' then
			local ip = ffi.cast('struct sockaddr_in6*', self.ai_addr).sin6_addr.s6_addr
			--TODO: find first longest sequence of all-zero 16bit components
			--and compress them all into a single '::'.
			return string.format('%x:%x:%x:%x:%x:%x:%x:%x',
				ip[ 0]*0x100+ip[ 1], ip[ 2]*0x100+ip[ 3], ip[ 4]*0x100+ip[ 5], ip[ 6]*0x100+ip[ 7],
				ip[ 8]*0x100+ip[ 9], ip[10]*0x100+ip[11], ip[12]*0x100+ip[13], ip[14]*0x100+ip[15])
		else
			return str(self.ai_addr, self.ai_addrlen)
		end
	end

	ffi.metatype(addrinfo_ct, {__index = ai})

end

--binding --------------------------------------------------------------------

ffi.cdef[[
int bind(SOCKET s, const sockaddr*, int namelen);
]]

function socket:bind(...)
	local ai, err = M.addr(...)
	if not ai then return false, err end
	local ok = C.bind(self.s, ai.ai_addr, ai.ai_addrlen) == 0
	if not err then ai:free() end
	if not ok then return check(false) end
	self._bound = true
	return true
end

--Windows/IOCP ---------------------------------------------------------------

if Windows then

require'winapi.types'

ffi.cdef[[

// IOCP ----------------------------------------------------------------------

typedef struct _OVERLAPPED {
	ULONG_PTR Internal;
	ULONG_PTR InternalHigh;
	PVOID Pointer;
	HANDLE    hEvent;
} OVERLAPPED, *LPOVERLAPPED;

HANDLE CreateIoCompletionPort(
	HANDLE    FileHandle,
	HANDLE    ExistingCompletionPort,
	ULONG_PTR CompletionKey,
	DWORD     NumberOfConcurrentThreads
);

BOOL GetQueuedCompletionStatus(
  HANDLE       CompletionPort,
  LPDWORD      lpNumberOfBytesTransferred,
  PULONG_PTR   lpCompletionKey,
  LPOVERLAPPED *lpOverlapped,
  DWORD        dwMilliseconds
);

// Sockets -------------------------------------------------------------------

typedef HANDLE WSAEVENT;
typedef unsigned int GROUP;

typedef struct _WSAPROTOCOL_INFOW WSAPROTOCOL_INFOW, *LPWSAPROTOCOL_INFOW;

SOCKET WSASocketW(
  int                 af,
  int                 type,
  int                 protocol,
  LPWSAPROTOCOL_INFOW lpProtocolInfo,
  GROUP               g,
  DWORD               dwFlags
);
int closesocket(SOCKET s);
int ioctlsocket(SOCKET s, long cmd, u_long *argp);

typedef struct WSAData {
	WORD wVersion;
	WORD wHighVersion;
	char szDescription[257];
	char szSystemStatus[129];
	unsigned short iMaxSockets; // to be ignored
	unsigned short iMaxUdpDg;   // to be ignored
	char *lpVendorInfo;         // to be ignored
} WSADATA, *LPWSADATA;

int WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);
int WSACleanup(void);
int WSAGetLastError();

typedef struct _WSABUF {
  ULONG len;
  CHAR  *buf;
} WSABUF, *LPWSABUF;

int WSAIoctl(
  SOCKET        s,
  DWORD         dwIoControlCode,
  LPVOID        lpvInBuffer,
  DWORD         cbInBuffer,
  LPVOID        lpvOutBuffer,
  DWORD         cbOutBuffer,
  LPDWORD       lpcbBytesReturned,
  LPOVERLAPPED  lpOverlapped,
  void*         lpCompletionRoutine
);

typedef BOOL (*LPFN_CONNECTEX) (
	SOCKET s,
	const sockaddr* name,
	int namelen,
	PVOID lpSendBuffer,
	DWORD dwSendDataLength,
	LPDWORD lpdwBytesSent,
	LPOVERLAPPED lpOverlapped
);

int WSASend(
	SOCKET       s,
	LPWSABUF     lpBuffers,
	DWORD        dwBufferCount,
	LPDWORD      lpNumberOfBytesSent,
	DWORD        dwFlags,
	LPOVERLAPPED lpOverlapped,
	void*        lpCompletionRoutine
);

int WSARecv(
	SOCKET       s,
	LPWSABUF     lpBuffers,
	DWORD        dwBufferCount,
	LPDWORD      lpNumberOfBytesRecvd,
	LPDWORD      lpFlags,
	LPOVERLAPPED lpOverlapped,
	void*        lpCompletionRoutine
);

int WSASendTo(
	SOCKET          s,
	LPWSABUF        lpBuffers,
	DWORD           dwBufferCount,
	LPDWORD         lpNumberOfBytesSent,
	DWORD           dwFlags,
	const sockaddr  *lpTo,
	int             iTolen,
	LPOVERLAPPED    lpOverlapped,
	void*           lpCompletionRoutine
);

int WSARecvFrom(
	SOCKET       s,
	LPWSABUF     lpBuffers,
	DWORD        dwBufferCount,
	LPDWORD      lpNumberOfBytesRecvd,
	LPDWORD      lpFlags,
	sockaddr*    lpFrom,
	LPINT        lpFromlen,
	LPOVERLAPPED lpOverlapped,
	void*        lpCompletionRoutine
);

BOOL AcceptEx(
	SOCKET       sListenSocket,
	SOCKET       sAcceptSocket,
	PVOID        lpOutputBuffer,
	DWORD        dwReceiveDataLength,
	DWORD        dwLocalAddressLength,
	DWORD        dwRemoteAddressLength,
	LPDWORD      lpdwBytesReceived,
	LPOVERLAPPED lpOverlapped
);

void GetAcceptExSockaddrs(
	PVOID      lpOutputBuffer,
	DWORD      dwReceiveDataLength,
	DWORD      dwLocalAddressLength,
	DWORD      dwRemoteAddressLength,
	sockaddr** LocalSockaddr,
	LPINT      LocalSockaddrLength,
	sockaddr** RemoteSockaddr,
	LPINT      RemoteSockaddrLength
);
]]

local nbuf = ffi.new'DWORD[1]' --global buffer shared between many calls.

do --init winsock library.
	local WSADATA = ffi.new'WSADATA'
	assert(C.WSAStartup(0x101, WSADATA) == 0)
	assert(WSADATA.wVersion == 0x101)
end

--error handling

do
	ffi.cdef[[
	DWORD FormatMessageA(
		DWORD dwFlags,
		LPCVOID lpSource,
		DWORD dwMessageId,
		DWORD dwLanguageId,
		LPSTR lpBuffer,
		DWORD nSize,
		va_list *Arguments
	);
	]]

	local FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000

	local errbuf = glue.buffer'char[?]'

	local error_classes = {
		[10013] = 'access_denied',
	}

	function check(ret)
		if ret then return ret end
		local err = C.WSAGetLastError()
		local msg = error_classes[err]
		if not msg then
			local buf, bufsz = errbuf(256)
			local sz = ffi.C.FormatMessageA(
				FORMAT_MESSAGE_FROM_SYSTEM, nil, err, 0, buf, bufsz, nil)
			msg = sz > 0 and ffi.string(buf, sz):gsub('[\r\n]+$', '') or 'Error '..err
		end
		return nil, msg, err
	end
end

--NOTE: IOCPs can be shared between threads and having a single IOCP for all
--threads is more efficient for the kernel than having one IOCP per thread.
--To share the IOCP with another Lua state, get it with socket.iocp(), then
--copy it over, then set it with socket.iocp(copied_iocp).
local iocp
function M.iocp(shared_iocp)
	if shared_iocp then
		iocp = shared_iocp
	elseif not iocp then
		local INVALID_HANDLE_VALUE = ffi.cast('HANDLE', -1)
		iocp = ffi.C.CreateIoCompletionPort(INVALID_HANDLE_VALUE, nil, 0, 0)
		assert(check(M.iocp ~= nil))
	end
	return iocp
end

--Binding ConnectEx() because WSAConnect() doesn't do IOCP.
local function ConnectEx(s, ...)

	local IOC_OUT = 0x40000000
	local IOC_IN  = 0x80000000
	local IOC_WS2 = 0x08000000
	local SIO_GET_EXTENSION_FUNCTION_POINTER = bit.bor(IOC_IN, IOC_OUT, IOC_WS2, 6)
	local WSAID_CONNECTEX = ffi.new('GUID',
		0x25a207b9,0xddf3,0x4660,{0x8e,0xe9,0x76,0xe5,0x8c,0x74,0x06,0x3e})

	local cbuf = ffi.new'LPFN_CONNECTEX[1]'

	assert(check(C.WSAIoctl(
		s, SIO_GET_EXTENSION_FUNCTION_POINTER,
		WSAID_CONNECTEX, ffi.sizeof(WSAID_CONNECTEX),
		cbuf, ffi.sizeof(cbuf),
		nbuf, nil, nil
	)) == 0)
	assert(cbuf[0] ~= nil)

	ConnectEx = cbuf[0] --replace this loader.

	return ConnectEx(s, ...)
end

local tcp = {}
local udp = {}

do

	local WSA_FLAG_OVERLAPPED             = 0x01
	--local WSA_FLAG_NO_HANDLE_INHERIT      = 0x80

	local function new(methods, socktype, family, protocol)

		family = family or 'inet'
		local st, af, prot = socketargs(socktype, family, protocol)
		assert(st ~= 0, 'socket type required')
		local flags = WSA_FLAG_OVERLAPPED

		local s = C.WSASocketW(af, st, prot, nil, 0, flags)

		if s == INVALID_SOCKET then
			return check()
		end

		local iocp = M.iocp()
		if ffi.C.CreateIoCompletionPort(ffi.cast('HANDLE', s), iocp, 0, 0) ~= iocp then
			return check()
		end

		local s = {s = s, __index = socket,
			type = socktype, family = family, protocol = protocol,
			_st = st, _af = af, _prot = prot,
		}
		glue.update(s, methods)
		wrap_socket(s)

		return setmetatable(s, s)
	end
	function M.tcp(...) return new(tcp, 'tcp', ...) end
	function M.udp(...) return new(udp, 'udp', ...) end

end

do
	local FIONBIO = bit.tobit(0x8004667e)

	local ulongbuf = ffi.new'u_long[1]'

	function socket:setblocking(blocking)
		ulongbuf[0] = blocking and 0 or 1
		assert(check(C.ioctlsocket(self.s, FIONBIO, ulongbuf) == 0))
	end
end

function socket:close()
	C.closesocket(self.s)
end

local overlapped, free_overlapped
local OVERLAPPED = ffi.typeof'OVERLAPPED'
local LPOVERLAPPED = ffi.typeof'LPOVERLAPPED'

do
	local jobs = {} --{job1, ...}
	local freed = {} --{job_index1, ...}
	local push = table.insert
	local pop = table.remove
	local overlapped_ct = ffi.typeof[[
		struct {
			OVERLAPPED overlapped;
			int job_index;
		}
	]]
	local overlapped_ptr_ct = ffi.typeof('$*', overlapped_ct)
	function overlapped()
		if #freed > 0 then
			local job_index = pop(freed)
			local job = jobs[job_index]
			local o = ffi.cast(LPOVERLAPPED, job._overlapped)
			ffi.fill(o, ffi.sizeof(OVERLAPPED))
			return o, job
		else
			local job = {}
			local o = overlapped_ct()
			job._overlapped = o
			push(jobs, job)
			o.job_index = #jobs
			return ffi.cast(LPOVERLAPPED, o), job
		end
	end
	function free_overlapped(o)
		local o = ffi.cast(overlapped_ptr_ct, o)
		push(freed, o.job_index)
		return jobs[o.job_index]
	end
end

do
	local keybuf = ffi.new'ULONG_PTR[1]'
	local obuf = ffi.new'LPOVERLAPPED[1]'

	function M.poll(timeout)
		timeout = glue.clamp(timeout or 1/0, 0, 0xFFFFFFFF)
		local ok = ffi.C.GetQueuedCompletionStatus(
			iocp, nbuf, keybuf, obuf, timeout * 1000) ~= 0
		if not ok then return check() end
		local o = obuf[0]
		local n = nbuf[0]
		return free_overlapped(o), n
	end
end

do
	local WSA_IO_PENDING = 997

	local function check_pending(ok, job)
		if not ok and C.WSAGetLastError() ~= WSA_IO_PENDING then
			return check(false)
		end
		return true, job
	end

	function socket:connect(...)
		if not self._bound then
			--ConnectEx requires binding first.
			local ok, err, errcode = self:bind(nil, 0, self._st, self._af, self._prot)
			if not ok then return nil, err, errcode end
		end
		local ai, err = M.addr(...)
		if not ai then return false, err end
		local o, job = overlapped()
		local ok = ConnectEx(self.s, ai.ai_addr, ai.ai_addrlen, nil, 0, nil, o) == 1
		if not err then ai:free() end
		return check_pending(ok, job)
	end

	local wsabuf = ffi.new'WSABUF'

	local pchar_t = ffi.typeof'char*'
	local flagsbuf = ffi.new'DWORD[1]'

	function tcp:send(buf, len)
		wsabuf.buf = type(buf) == 'string' and ffi.cast(pchar_t, buf) or buf
		wsabuf.len = len or #buf
		local o, job = overlapped()
		local ok = C.WSASend(self.s, wsabuf, 1, nbuf, 0, o, nil) == 0
		return check_pending(ok, job)
	end

	function udp:send(buf, len, ...)
		local ai, err = M.addr(...)
		wsabuf.buf = type(buf) == 'string' and ffi.cast(pchar_t, buf) or buf
		wsabuf.len = len or #buf
		local o, job = overlapped()
		local ok = C.WSASendTo(self.s, wsabuf, 1, nbuf, 0, ai.ai_addr, ai.ai_addrlen, o, nil) == 0
		if not err then ai:free() end
		return check_pending(ok, job)
	end

	function tcp:recv(buf, len)
		wsabuf.buf = buf
		wsabuf.len = len
		local o, job = overlapped()
		flagsbuf[0] = 0
		local ok = C.WSARecv(self.s, wsabuf, 1, nbuf, flagsbuf, o, nil) == 0
		return check_pending(ok, job)
	end

	function udp:recv(buf, len, ...)
		local ai, err = M.addr(...)
		wsabuf.buf = buf
		wsabuf.len = len
		local o, job = overlapped()
		flagsbuf[0] = 0
		local ok = C.WSARecvFrom(self.s, wsabuf, 1, nbuf, flagsbuf, ai.ai_addr, ai.ai_addrlen, o, nil) == 0
		if not err then ai:free() end
		return check_pending(ok, job)
	end

end

end --Windows

--berkley sockets ------------------------------------------------------------

if not Windows then

ffi.cdef[[
SOCKET socket(int af, int type, int protocol);
SOCKET accept(SOCKET s, struct sockaddr *addr, int *addrlen);
int bind(SOCKET s, const struct sockaddr *name, int namelen);
int close(SOCKET s);
int connect(SOCKET s, const struct sockaddr *name, int namelen);
int ioctl(SOCKET s, long cmd, u_long *argp);
int listen(SOCKET s, int backlog);
int recv(SOCKET s, char *buf, int len, int flags);
int recvfrom(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen);
int send(SOCKET s, const char *buf, int len, int flags);
int sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen);
int shutdown(SOCKET s, int how);
]]

local tcp = {}
local udp = {}

function M.new(l4_type, l3_type)
	local type = SOCK(l4_type)
	local af = AF(l3_type)
	local s = C.socket(af, type, 0)
	if s == INVALID_SOCKET then
		return check()
	end
	local s = {s = s, __index = socket}
	glue.update(s, methods[l4_type])
	return setmetatable(s, s)
end

local EINPROGRESS = 115

function socket:connect(ip, port, l3_type)
	local sa, err = M.addr(host, port, l3_type)
	if not sa then
		return false, err
	end
	local ret = C.connect(s, sa, ffi.sizeof(sa))
	if ret == 0 then
		return true
	elseif ffi.errno ~= EINPROGRESS then
		return check(false)
	else
		return true, true --TODO: async
	end
end

function socket:close()
	return check(C.close(self.s) == 0)
end

function tcp:recv(buf, len)
	C.recv(self.s, buf, len, 0)
end

function tcp:send(buf, len)
	--int C.send(self.s, buf, len, flags);
end

function udp:recv(buf, len)
	--int C.recvfrom(self.s, buf, len, flags, struct sockaddr *from, int *fromlen);
end

function udp:send(buf, len)
	--int C.sendto(self.s, buf, len, flags, const struct sockaddr *to, int tolen);
end

end --not Windows

--all/select -----------------------------------------------------------------

ffi.cdef[[
//int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout);
]]

--Linux/epoll ----------------------------------------------------------------

if linux then

ffi.cdef[[
enum EPOLL_EVENTS {
	EPOLLIN = 0x001,
	EPOLLPRI = 0x002,
	EPOLLOUT = 0x004,
	EPOLLRDNORM = 0x040,
	EPOLLRDBAND = 0x080,
	EPOLLWRNORM = 0x100,
	EPOLLWRBAND = 0x200,
	EPOLLMSG = 0x400,
	EPOLLERR = 0x008,
	EPOLLHUP = 0x010,
	EPOLLRDHUP = 0x2000,
	EPOLLEXCLUSIVE = 1u << 28,
	EPOLLWAKEUP = 1u << 29,
	EPOLLONESHOT = 1u << 30,
	EPOLLET = 1u << 31
};

typedef union epoll_data {
	void *ptr;
	int fd;
	uint32_t u32;
	uint64_t u64;
} epoll_data_t;

struct epoll_event {
	uint32_t events;
	epoll_data_t data;
};

int epoll_create1(int flags);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
]]

local EPOLL_CTL_ADD = 1
local EPOLL_CTL_DEL = 2
local EPOLL_CTL_MOD = 3

end

--coroutine loop -------------------------------------------------------------

local loop = {}
M.loop = loop

function loop.resume(thread, ...)
	local loop_thread = loop.thread
	--change loop.thread temporarily so that we get back here
	--on the first call to suspend().
	loop.thread = coro.running()
	coro.transfer(thread, ...)
	loop.thread = loop_thread
end

--create a thread set up to transfer control to the loop thread on finish,
--and run it. return it while suspended in the first async socket call.
--step() will resume it afterwards.
function newthread(handler, ...)
	--wrap handler so that it terminates in current loop.thread.
	local handler = function(...)
		handler(...)
		coro.transfer(loop.thread)
	end
	local thread = coro.create(handler)
	loop.resume(thread, ...)
	return thread
end
function loop.newthread(handler, ...)
	--wrap handler to get full traceback from coroutine.
	local handler = function(...)
		local ok, err = glue.pcall(handler, ...)
		if ok then return ok end
		error(err, 2)
	end
	return newthread(handler, ...)
end

local function wrap_method(skt, method)
	local inherited = skt[method]
	if not inherited then return end
	skt[method] = function(...)
		local ret, job = inherited(...)
		if not ret then return ret, job end
		job.thread = coro.running()
		return coro.transfer(loop.thread)
	end
end
--[[local]] function wrap_socket(skt)
	wrap_method(skt, 'connect')
	wrap_method(skt, 'send'   )
	wrap_method(skt, 'recv'   )
end

function loop.poll(timeout)
	local job, n, errcode = M.poll(timeout)
	if not job then return nil, n, errcode end
	loop.thread = coro.running()
	coro.resume(job.thread, n)
	return true
end

local stop = false
function loop.stop() stop = true end
function loop.start(timeout)
	repeat
		local ok, err, errcode = loop.poll(timeout)
		if not ok then return nil, err, errcode end
	until stop
	return true
end

return M
