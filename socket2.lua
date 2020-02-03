
--Portable socket API with IOCP and epoll for LuaJIT.
--Written by Cosmin Apreutesei. Public Domain.

if not ... then require'socket2_test'; return end

local ffi = require'ffi'
local bit = require'bit'
local glue = require'glue'

local bswap = bit.bswap
local shr = bit.rshift
local pass1 = function(x) return x end

local C
local M = {}
local socket = {}

local check --fw. decl.
local function checkz(ret) return check(ret == 0) end
local function checknz(ret) return check(ret ~= 0) end

local INVALID_SOCKET = ffi.cast('uintptr_t', -1)

ffi.cdef[[
typedef unsigned long u_long;
typedef void sockaddr;
typedef uintptr_t SOCKET;
]]

--hostname lookup ------------------------------------------------------------

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

uint32_t inet_addr(const char *cp);

typedef struct hostent {
	char *h_name;
	char **h_aliases;
	short h_addrtype;
	short h_length;
	char **h_addr_list;
};
struct hostent *gethostbyname(const char *name, int af);
]]

local htonl = ffi.abi'le' and bswap or pass1
local htons = ffi.abi'le' and function(x) return shr(bswap(x), 16) end or pass1

local AF_INET  = 2
local AF_INET6 = 23

local function AF(type)
	return ((not type or type == 'ipv4') and AF_INET)
		 or (type == 'ipv6' and AF_INET6)
		 or error'invalid ip type'
end

local SOCK_STREAM = 1
local SOCK_DGRAM  = 2

local function SOCK(type)
	return (type == 'udp' and SOCK_DGRAM)
		 or (type == 'tcp' and SOCK_STREAM)
		 or error'invalid socket type'
end

local function ip_lookup(host, l3_type)
	local af = AF(l3_type)
	local e = C.gethostbyname2(host, af)
	if e == nil then
		return nil, 'hostname lookup failed'
	end
	assert(e.h_addrtype == af)
	local ctype =
		   af == AF_INET  and 'in_addr**'
		or af == AF_INET6 and 'in6_addr**'
	return ffi.cast(ctype, e.h_addr_list), af
end

function M.ips(host, l3_type)
	local ips, af = ip_lookup(host, l3_type)
	if not ips then
		return nil, af
	end
	local t = {}
	local i = 0
	while ips[i] ~= nil do
		t[i+1] = af == AF_INET and ips[i].s_addr or ffi.string(ips[i].s6_addr)
		i = i + 1
	end
	return t
end

do
	local sockaddr_in  = ffi.typeof'struct sockaddr_in'
	local sockaddr_in6 = ffi.typeof'struct sockaddr6_in'

	function M.addr(host, port, l3_type)
		if type(host) == 'cdata' then
			return host --pass-through
		end
		local port = port and htons(port) or 0
		local ips, af
		if not host then
			af = AF(l3_type)
		else
			ips, af = ip_lookup(host, l3_type)
			if not ips then
				return nil, af
			end
		end
		local sa_ct = af == AF_INET and sockaddr_in or sockaddr6_in
		local sa = sa_ct(af, port)
		sa.sin_addr = ips[0]
		return sa
	end
end

--binding --------------------------------------------------------------------

ffi.cdef[[
int bind(SOCKET s, const sockaddr*, int namelen);
]]

function socket:bind(host, port, i3_type)
	local sa, err = M.addr(host, port, l3_type)
	if not sa then
		return false, err
	end
	if C.bind(self.s, sa, ffi.sizeof(sa)) ~= 0 then
		return check(false)
	end
	self._bound = true
	return true
end

--Windows/IOCP ---------------------------------------------------------------

if ffi.os == 'Windows' then

C = ffi.load'ws2_32'
M.C = C

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
		assert(M.iocp ~= nil, 'could not create an IOCP')
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

	assert(checkz(C.WSAIoctl(
		s, SIO_GET_EXTENSION_FUNCTION_POINTER,
		WSAID_CONNECTEX, ffi.sizeof(WSAID_CONNECTEX),
		cbuf, ffi.sizeof(cbuf),
		nbuf, nil, nil
	)))
	assert(cbuf[0] ~= nil)

	ConnectEx = cbuf[0] --replace this loader.

	return ConnectEx(s, ...)
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

do
	local IPPROTO_IP   =   0
	--local IPPROTO_ICMP =   1
	--local IPPROTO_IGMP =   2
	--local IPPROTO_TCP  =   6
	local IPPROTO_UDP  =  17
	--local IPPROTO_RAW  = 255

	local WSA_FLAG_OVERLAPPED             = 0x01
	--local WSA_FLAG_MULTIPOINT_C_ROOT      = 0x02
	--local WSA_FLAG_MULTIPOINT_C_LEAF      = 0x04
	--local WSA_FLAG_MULTIPOINT_D_ROOT      = 0x08
	--local WSA_FLAG_MULTIPOINT_D_LEAF      = 0x10
	--local WSA_FLAG_ACCESS_SYSTEM_SECURITY = 0x40
	--local WSA_FLAG_NO_HANDLE_INHERIT      = 0x80

	function M.new(l4_type, l3_type)

		--l3_type not needed on Windows but checked for cross-platform compat.
		AF(l3_type)

		local proto = l4_type == 'tcp' and IPPROTO_TCP or IPPROTO_UDP
		local flags = WSA_FLAG_OVERLAPPED
		local s = C.WSASocketW(AF_INET, SOCK(l4_type), proto, nil, 0, flags)
		if s == INVALID_SOCKET then
			return check()
		end

		assert(ffi.C.CreateIoCompletionPort(ffi.cast('HANDLE', s), M.iocp(), 0, 0) == M.iocp())

		local s = {s = s, __index = socket}
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

	function socket:connect(host, port, l3_type)
		if not self._bound then
			self:bind() --ConnectEx requires it.
		end
		local sa, err = M.addr(host, port, l3_type)
		if not sa then
			return false, err
		end
		local o, job = overlapped()
		local ret = ConnectEx(self.s, sa, ffi.sizeof(sa), nil, 0, nil, o)
		if ret == 1 then
			return true
		end
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

if ffi.os ~= 'Windows' then

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
int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout);
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
