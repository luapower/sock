
--Portable socket API with IOCP and epoll for LuaJIT.
--Written by Cosmin Apreutesei. Public Domain.

if not ... then require'socket2_test'; return end

local ffi = require'ffi'
local bit = require'bit'
local glue = require'glue'

local win = ffi.abi'win'
local linux = ffi.os == 'Linux'

local bswap = bit.bswap
local shr = bit.rshift
local pass1 = function(x) return x end

local C = win and ffi.load'ws2_32' or ffi.C
local M = {C = C}
local socket = {}

local check --fw. decl.

ffi.cdef[[
typedef unsigned long u_long;
typedef void sockaddr;
typedef uintptr_t SOCKET;
]]

local INVALID_SOCKET = ffi.cast('SOCKET', -1)

--sockaddr construction ------------------------------------------------------

ffi.cdef[[
struct in_addr {
	unsigned long s_addr;
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

if win then
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

local socketargs, addrinfo, freeaddrinfo
do
	local address_types = {
		inet = 2,
		inet6 = 23,
	}

	local socket_types = {
		tcp = 1,
		udp = 2,
	}

	local protocols = {
		ip = 0,
		icmp = 1,
		igmp = 2,
		tcp = 6,
		udp = 17,
		raw = 255,
	}

	local flag_bits = {
		passive     = win and 0x00000001 or 0x0001,
		cannonname  = win and 0x00000002 or 0x0002,
		numerichost = win and 0x00000004 or 0x0004,
		numericserv = win and 0x00000008 or 0x0400,
		all         = win and 0x00000100 or 0x0010,
		v4mapped    = win and 0x00000800 or 0x0008,
		addrconfig  = win and 0x00000400 or 0x0020,
	}

	function socketargs(socktype, family, protocol)
		socktype = socket_types[socktype] or socktype or 0
		family = address_types[family] or family or 0
		protocol = protocols[protocol] or protocol or 0
		return socktype, family, protocol
	end

	local hints = ffi.new'struct addrinfo'
	local addrs = ffi.new'struct addrinfo*[1]'

	function addrinfo(host, port, socket_type, address_type, protocol, flags)
		if type(host) == 'table' then
			local t = host
			host, port, address_type, socket_type, protocol, flags =
				t.host, t.port, t.address_type, t.socket_type, t.protocol, t.flags
		end
		ffi.fill(hints, ffi.sizeof(hints))
		hints.ai_socktype, hints.ai_family, hints.ai_protocol
			= socketargs(socket_type, address_type, protocol)
		hints.ai_flags = glue.bor(flags or 0, flag_bits, true)
		if type(port) == 'number' then
			hints.ai_flags = bit.bor(hints.ai_flags, flag_bits.numericserv)
		end
		local ret = C.getaddrinfo(host, port and tostring(port), hints, addrs)
		if ret ~= 0 then return check() end
		return addrs[0]
	end

	freeaddrinfo = C.freeaddrinfo
end

--binding --------------------------------------------------------------------

ffi.cdef[[
int bind(SOCKET s, const sockaddr*, int namelen);
]]

function socket:bind(...)
	local ai, err = addrinfo(...)
	if not ai then return false, err end
	local ok = C.bind(self.s, ai.ai_addr, ai.ai_addrlen) == 0
	freeaddrinfo(ai)
	if not ok then return check(false) end
	self._bound = true
	return true
end

--Windows/IOCP ---------------------------------------------------------------

if win then

require'winapi.types'

ffi.cdef[[

// IOCP ----------------------------------------------------------------------

typedef struct _OVERLAPPED {
  ULONG_PTR Internal;
  ULONG_PTR InternalHigh;
  union {
    struct {
      DWORD Offset;
      DWORD OffsetHigh;
    } DUMMYSTRUCTNAME;
    PVOID Pointer;
  } DUMMYUNIONNAME;
  HANDLE    hEvent;
} OVERLAPPED, *LPOVERLAPPED;

typedef struct _OVERLAPPED_ENTRY {
  ULONG_PTR    lpCompletionKey;
  LPOVERLAPPED lpOverlapped;
  ULONG_PTR    Internal;
  DWORD        dwNumberOfBytesTransferred;
} OVERLAPPED_ENTRY, *LPOVERLAPPED_ENTRY;

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

BOOL GetQueuedCompletionStatusEx(
	HANDLE             CompletionPort,
	LPOVERLAPPED_ENTRY lpCompletionPortEntries,
	ULONG              ulCount,
	PULONG             ulNumEntriesRemoved,
	DWORD              dwMilliseconds,
	BOOL               fAlertable
);

// Sockets -------------------------------------------------------------------

typedef HANDLE WSAEVENT;
typedef unsigned int GROUP;

typedef struct _WSAPROTOCOLCHAIN {
  int   ChainLen;
  DWORD ChainEntries[7];
} WSAPROTOCOLCHAIN, *LPWSAPROTOCOLCHAIN;

typedef struct _WSAPROTOCOL_INFOW {
  DWORD            dwServiceFlags1;
  DWORD            dwServiceFlags2;
  DWORD            dwServiceFlags3;
  DWORD            dwServiceFlags4;
  DWORD            dwProviderFlags;
  GUID             ProviderId;
  DWORD            dwCatalogEntryId;
  WSAPROTOCOLCHAIN ProtocolChain;
  int              iVersion;
  int              iAddressFamily;
  int              iMaxSockAddr;
  int              iMinSockAddr;
  int              iSocketType;
  int              iProtocol;
  int              iProtocolMaxOffset;
  int              iNetworkByteOrder;
  int              iSecurityScheme;
  DWORD            dwMessageSize;
  DWORD            dwProviderReserved;
  WCHAR            szProtocol[8];
} WSAPROTOCOL_INFOW, *LPWSAPROTOCOL_INFOW;

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

typedef ULONG SERVICETYPE;

typedef struct _flowspec {
	ULONG       TokenRate;              /* In Bytes/sec */
	ULONG       TokenBucketSize;        /* In Bytes */
	ULONG       PeakBandwidth;          /* In Bytes/sec */
	ULONG       Latency;                /* In microseconds */
	ULONG       DelayVariation;         /* In microseconds */
	SERVICETYPE ServiceType;
	ULONG       MaxSduSize;             /* In Bytes */
	ULONG       MinimumPolicedSize;     /* In Bytes */
} FLOWSPEC, *LPFLOWSPEC;

typedef struct _QualityOfService {
	FLOWSPEC      SendingFlowspec;       /* the flow spec for data sending */
	FLOWSPEC      ReceivingFlowspec;     /* the flow spec for data receiving */
	WSABUF        ProviderSpecific;      /* additional provider specific stuff */
} QOS, *LPQOS;

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

do

	local WSA_FLAG_OVERLAPPED             = 0x01
	--local WSA_FLAG_NO_HANDLE_INHERIT      = 0x80

	function M.new(socktype, family, protocol)

		family = family or 'inet'
		local socktype, family, protocol = socketargs(socktype, family, protocol)
		assert(family ~= 0, 'address family required')
		assert(socktype ~= 0, 'socket type required')
		local flags = WSA_FLAG_OVERLAPPED

		local s = C.WSASocketW(family, socktype, protocol, nil, 0, flags)

		if s == INVALID_SOCKET then
			return check()
		end

		local iocp = M.iocp()
		if ffi.C.CreateIoCompletionPort(ffi.cast('HANDLE', s), iocp, 0, 0) ~= iocp then
			return check()
		end

		local s = {s = s, __index = socket,
			_socktype = socktype, _family = family, _protocol = protocol}
		return setmetatable(s, s)
	end
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
do
	local list_dynarray  = glue.dynarray'OVERLAPPED[?]'
	local freed_dynarray = glue.dynarray'int[?]'
	local list
	local freed
	local list_top  = -1
	local freed_top = -1
	local jobs = {}
	function overlapped()
		if freed_top >= 0 then
			local i = freed[freed_top]
			freed_top = freed_top - 1
			return list + i, jobs[i + 1]
		else
			list_top = list_top + 1
			list = list_dynarray(list_top + 1)
			local job = {}; jobs[list_top + 1] = job
			return list + list_top, job
		end
	end
	function free_overlapped(o)
		local i = o - list
		freed_top = freed_top + 1
		freed = freed_dynarray(freed_top + 1)
		freed[freed_top] = i
		return jobs[i]
	end
end

do
	local keybuf = ffi.new'ULONG_PTR[1]'
	local obuf = ffi.new'LPOVERLAPPED[1]'

	function M.poll(timeout)
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

	local function check_pending(job)
		local err = C.WSAGetLastError()
		if err == WSA_IO_PENDING then
			return true, job
		else
			return check(false)
		end
	end

	function socket:connect(...)
		if not self._bound then
			--ConnectEx requires binding first.
			local ok, err, errcode = self:bind(nil, 0,
				self._socktype, self._family, self._protocol)
			if not ok then return nil, err, errcode end
		end
		local ai, err = addrinfo(...)
		if not ai then return false, err end
		local o, job = overlapped()
		local ok = ConnectEx(self.s, ai.ai_addr, ai.ai_addrlen, nil, 0, nil, o) == 1
		freeaddrinfo(ai)
		if ok then return true end
		return check_pending(job)
	end

	local wsabuf = ffi.new'WSABUF'

	local pchar_t = ffi.typeof'char*'
	function socket:send(buf, len)
		wsabuf.buf = type(buf) == 'string' and ffi.cast(pchar_t, buf) or buf
		wsabuf.len = len or #buf
		local o, job = overlapped()
		if C.WSASend(self.s, wsabuf, 1, nbuf, 0, o, nil) == 0 then
			return nbuf[0]
		end
		return check_pending(job)
	end

	local flagsbuf = ffi.new'DWORD[1]'
	function socket:recv(buf, len)
		wsabuf.buf = buf
		wsabuf.len = len
		local o, job = overlapped()
		if C.WSARecv(self.s, wsabuf, 1, nbuf, flagsbuf, o, nil) == 0 then
			return nbuf[0]
		end
		return check_pending(job)
	end
end

end --Windows

--berkley sockets ------------------------------------------------------------

if not win then

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

local methods = {tcp = {}, udp = {}}

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

function methods.tcp:recv(buf, len)
	C.recv(self.s, buf, len, 0)
end

function methods.tcp:send(buf, len)
	--int C.send(self.s, buf, len, flags);
end

function methods.udp:recv(buf, len)
	--int C.recvfrom(self.s, buf, len, flags, struct sockaddr *from, int *fromlen);
end

function methods.udp:send(buf, len)
	--int C.sendto(self.s, buf, len, flags, const struct sockaddr *to, int tolen);
end

end --not Windows

--all/select -----------------------------------------------------------------

ffi.cdef[[
//int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout);
]]

--Linux/epoll ----------------------------------------------------------------

if ffi.os == 'Linux' then

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

return M
