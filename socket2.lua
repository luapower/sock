
--Portable socket API with IOCP and epoll for LuaJIT.
--Written by Cosmin Apreutesei. Public Domain.

if not ... then require'socket2_test'; return end

local ffi = require'ffi'
local bit = require'bit'

local bswap = bit.bswap
local shr = bit.rshift

local pass1 = function(x) return x end

local htonl = ffi.abi'le' and bswap or pass1
local htons = ffi.abi'le' and function(x) return shr(bswap(x), 16) end or pass1

local AF_INET  = 2
local AF_INET6 = 23

local SOCK_STREAM = 1
local SOCK_DGRAM  = 2

local C
local M = {}
local socket = {}

local function checkz(ret)
	return check(ret == 0)
end

--common ---------------------------------------------------------------------

ffi.cdef'uint32_t inet_addr(const char *cp);'

function M.ipv4(s)
	if not s then return nil end
	local n = C.inet_addr(s)
	return n ~= 2^32-1 and n or nil
end

local sockaddr_in = ffi.typeof[[
	struct {
		int16_t  sin_family;
		uint16_t sin_port;
		uint32_t sin_addr;
		char     sin_zero[8];
	}
]]

if ffi.abi'win' then

--Windows --------------------------------------------------------------------

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

typedef uintptr_t SOCKET;
typedef HANDLE WSAEVENT;
typedef unsigned int GROUP;
typedef void* sockaddr_ptr;
typedef unsigned long u_long;

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
int bind(SOCKET s, const sockaddr_ptr, int namelen);
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

typedef struct _WSAOVERLAPPED {
  DWORD    Internal;
  DWORD    InternalHigh;
  DWORD    Offset;
  DWORD    OffsetHigh;
  WSAEVENT hEvent;
} WSAOVERLAPPED, *LPWSAOVERLAPPED;

typedef void (*LPWSAOVERLAPPED_COMPLETION_ROUTINE)(
	DWORD dwError,
	DWORD cbTransferred,
	LPWSAOVERLAPPED lpOverlapped,
	DWORD dwFlags
);

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
  SOCKET                             s,
  DWORD                              dwIoControlCode,
  LPVOID                             lpvInBuffer,
  DWORD                              cbInBuffer,
  LPVOID                             lpvOutBuffer,
  DWORD                              cbOutBuffer,
  LPDWORD                            lpcbBytesReturned,
  LPWSAOVERLAPPED                    lpOverlapped,
  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

typedef BOOL (*LPFN_CONNECTEX) (
	SOCKET s,
	const sockaddr_ptr name,
	int namelen,
	PVOID lpSendBuffer,
	DWORD dwSendDataLength,
	LPDWORD lpdwBytesSent,
	LPOVERLAPPED lpOverlapped
);

int WSASend(
	SOCKET                             s,
	LPWSABUF                           lpBuffers,
	DWORD                              dwBufferCount,
	LPDWORD                            lpNumberOfBytesSent,
	DWORD                              dwFlags,
	LPWSAOVERLAPPED                    lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

int WSARecv(
	SOCKET                             s,
	LPWSABUF                           lpBuffers,
	DWORD                              dwBufferCount,
	LPDWORD                            lpNumberOfBytesRecvd,
	LPDWORD                            lpFlags,
	LPWSAOVERLAPPED                    lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

int WSARecvFrom(
	SOCKET                             s,
	LPWSABUF                           lpBuffers,
	DWORD                              dwBufferCount,
	LPDWORD                            lpNumberOfBytesRecvd,
	LPDWORD                            lpFlags,
	sockaddr_ptr                       lpFrom,
	LPINT                              lpFromlen,
	LPWSAOVERLAPPED                    lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
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
	PVOID    lpOutputBuffer,
	DWORD    dwReceiveDataLength,
	DWORD    dwLocalAddressLength,
	DWORD    dwRemoteAddressLength,
	sockaddr_ptr *LocalSockaddr,
	LPINT    LocalSockaddrLength,
	sockaddr_ptr *RemoteSockaddr,
	LPINT    RemoteSockaddrLength
);
]]

local function ConnectEx(s, ...)

	local IOC_OUT = 0x40000000
	local IOC_IN  = 0x80000000
	local IOC_WS2 = 0x08000000
	local SIO_GET_EXTENSION_FUNCTION_POINTER = bit.bor(IOC_IN, IOC_OUT, 6)
	local WSAID_CONNECTEX = ffi.new('GUID',
		0x25a207b9,0xddf3,0x4660,{0x8e,0xe9,0x76,0xe5,0x8c,0x74,0x06,0x3e})

	local cbuf = ffi.new'LPFN_CONNECTEX[1]'
	local nbuf = ffi.new'DWORD[1]'

	assert(checkz(C.WSAIoctl(
		s, SIO_GET_EXTENSION_FUNCTION_POINTER,
		WSAID_CONNECTEX, ffi.sizeof(WSAID_CONNECTEX),
		cbuf, ffi.sizeof(cbuf),
		nbuf, nil, nil
	)))
	assert(cbuf[0] ~= nil)

	ConnectEx = cbuf[0] --replace this loader.

	return ConnectEx(...)
end

do
	local WSADATA = ffi.new'WSADATA'
	assert(C.WSAStartup(0x101, WSADATA) == 0)
	assert(WSADATA.wVersion == 0x101)
end

local OVERLAPPED = ffi.typeof'WSAOVERLAPPED'
local WSABUF     = ffi.typeof'WSABUF'

--error handling

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

--static, auto-growing buffer allocation pattern (ctype must be vla).
local function buffer(ctype)
	local vla = ffi.typeof(ctype)
	local buf, len = nil, -1
	return function(minlen)
		if minlen == false then
			buf, len = nil, -1
		elseif minlen > len then
			len = glue.nextpow2(minlen)
			buf = vla(len)
		end
		return buf, len
	end
end
local errbuf = buffer'char[?]'

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

local INVALID_SOCKET = ffi.cast('uintptr_t', -1)

local IPPROTO_IP   =   0
local IPPROTO_ICMP =   1
local IPPROTO_IGMP =   2
local IPPROTO_TCP  =   6
local IPPROTO_UDP  =  17
local IPPROTO_RAW  = 255

local WSA_FLAG_OVERLAPPED             = 0x01
local WSA_FLAG_MULTIPOINT_C_ROOT      = 0x02
local WSA_FLAG_MULTIPOINT_C_LEAF      = 0x04
local WSA_FLAG_MULTIPOINT_D_ROOT      = 0x08
local WSA_FLAG_MULTIPOINT_D_LEAF      = 0x10
local WSA_FLAG_ACCESS_SYSTEM_SECURITY = 0x40
local WSA_FLAG_NO_HANDLE_INHERIT      = 0x80

function M.new(type)
	local s
	local flags = WSA_FLAG_OVERLAPPED
	if type == 'tcp' then
		s = C.WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nil, 0, flags)
	elseif type == 'udp' then
		s = C.WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nil, 0, flags)
	else
		assert(false)
	end
	if s == INVALID_SOCKET then
		return check()
	end
	local s = {s = s, __index = socket}
	return setmetatable(s, s)
end

local argb = ffi.new'u_long[1]'
local FIONBIO = bit.tobit(0x8004667e)

function socket:setblocking(blocking)
	argb[0] = blocking and 0 or 1
	assert(check(C.ioctlsocket(self.s, FIONBIO, argb) == 0))
end

function socket:close()
	C.closesocket(self.s)
end

local SOCKET_ERROR = -1
local WSAEWOULDBLOCK = 10035
local WSAEINPROGRESS = 10036

function socket:bind(ip, port)
	local sa = sockaddr_in(AF_INET, htons(port), M.ipv4(ip) or 0)
	return check(C.bind(self.s, sa, ffi.sizeof(sa)))
end

function socket:connect(ip, port)
	local sa = sockaddr_in(AF_INET, htons(port), assert(M.ipv4(ip)))
	local o = OVERLAPPED()
	local ret = ConnectEx(self.s, sa, ffi.sizeof(sa), nil, 0, 0, o)
	if ret == 0 then
		return true
	end
	local err = C.WSAGetLastError()
	if err == WSAEWOULDBLOCK or err == WSAEINPROGRESS then
		return true
	end
	return check(false)
end

local nbuf = ffi.new'DWORD[1]'
local flagsbuf = ffi.new'DWORD[1]'
local wsabuf = WSABUF()
local pchar_t = ffi.typeof'char*'

function socket:send(buf, len)
	wsabuf.buf = type(buf) == 'string' and ffi.cast(pchar_t, buf) or buf
	wsabuf.len = len or #buf
	local o = OVERLAPPED()
	return check(C.WSASend(self.s, wsabuf, 1, nbuf, 0, o, nil) == 0 and nbuf[0])
end

function socket:recv(buf, len)
	wsabuf.buf = buf
	wsabuf.len = len
	local o = OVERLAPPED()
	return check(C.WSARecv(self.s, wsabuf, 1, nbuf, flagsbuf, o, nil) == 0 and nbuf[0])
end

else

--posix ----------------------------------------------------------------------

end

return M
