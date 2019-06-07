
--Portable socket API with IOCP and epoll for LuaJIT.
--Written by Cosmin Apreutesei. Public Domain.

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

local function parse_ip(s)
	if type(s) == 'number' then --assume ipv4
		return s, 4
	elseif s:find('.', 1, true) then --ipv4
		local a, b, c, d = s:match'^(%d)%.(%d)%.(%d)%.(%d)$'
		if not a then return nil end
		return a * 2^24 + b * 2^16 + c * 2^8 + d, 4
	else --ipv6
		--TODO:
		return s, 6
	end
end

local M = {}

if ffi.abi'win' then

--Windows --------------------------------------------------------------------

local C = ffi.load'ws2_32'

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
typedef void* sockaddr_ptr;

SOCKET socket(int af, int type, int protocol);
int closesocket(SOCKET s);
int bind(SOCKET s, const sockaddr_ptr, int namelen);

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

local WSADATA = ffi.new'WSADATA'
C.WSAStartup(0x101, WSADATA)
assert(WSADATA.wVersion == 0x101)

local wsa_errors = {
	--
}

local function check(ret)
	if ret then return ret end
	local err = C.WSAGetLastError()
	return nil, wsa_errors[err] or err
end

local function checkz(ret)
	return check(ret == 0)
end

local INVALID_SOCKET = ffi.cast('uintptr_t', -1)

function M.socket(type)
	local s
	if type == 'tcp' then
		s = C.socket(AF_INET, SOCK_STREAM, 0)
	elseif type == 'udp' then
		s = C.socket(AF_INET, SOCK_DGRAM, 0)
	else
		assert(false)
	end
	return check(s ~= INVALID_SOCKET and s)
end

function M.close(s)
	C.closesocket(s)
end

else

--posix ----------------------------------------------------------------------




end

--common ---------------------------------------------------------------------

local sockaddr_in = ffi.typeof[[
	struct {
		int16_t  sin_family;
		uint16_t sin_port;
		uint32_t sin_addr;
		char     sin_zero[8];
	}
]]

function M.bind(s, ip, port)
	local sa = sockaddr_in()
	sa.sin_family = AF_INET
	sa.sin_addr = ip and parse_ip(ip) or 0
	sa.sin_port = htons(port)
	return checkz(C.bind(s, sa, ffi.sizeof(sa)))
end

--hi-level API ---------------------------------------------------------------



--self-test ------------------------------------------------------------------

if not ... then
	local sock = M
	local s = assert(sock.socket'tcp')
	assert(sock.bind(s, '127.0.0.1', 80))
	sock.close(s)
end

return M
