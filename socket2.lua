
--Portable socket API with IOCP, epoll and kqueue for LuaJIT.
--Written by Cosmin Apreutesei. Public Domain.

if not ... then
	require'http_client_test'
	--require'socket2_test'
	; return
end

local ffi = require'ffi'
local bit = require'bit'

local glue = require'glue'
local heap = require'heap'
local coro = require'coro'
local time = require'time'

local push = table.insert
local pop = table.remove

local Windows = ffi.os == 'Windows'
local Linux   = ffi.os == 'Linux'
local OSX     = ffi.os == 'OSX'

assert(Windows or Linux or OSX, 'unsupported platform')

local C = Windows and ffi.load'ws2_32' or ffi.C
local M = {C = C}

local socket = {issocket = true} --common socket methods
local tcp = {} --methods of tcp sockets
local udp = {} --methods of udp sockets
local raw = {} --methods of raw sockets

--forward declarations
local check, poll, wait, create_socket, wrap_socket

local function str(s, len)
	if s == nil then return nil end
	return ffi.string(s, len)
end

--getaddrinfo() --------------------------------------------------------------

ffi.cdef[[
struct sockaddr_in {
	short          family_num;
	uint8_t        port_bytes[2];
	uint8_t        ip_bytes[4];
	char           _zero[8];
};

struct sockaddr_in6 {
	short           family_num;
	uint8_t         port_bytes[2];
	unsigned long   flowinfo;
	uint8_t         ip_bytes[16];
	unsigned long   scope_id;
};

typedef struct sockaddr {
	union {
		struct {
			short   family_num;
			uint8_t port_bytes[2];
		};
		struct sockaddr_in  addr4;
		struct sockaddr_in6 addr6;
	};
} sockaddr;
]]

-- working around ABI blindness of C programmers...
if Windows then
	ffi.cdef[[
	struct addrinfo {
		int              flags;
		int              family_num;
		int              socktype_num;
		int              protocol_num;
		size_t           addrlen;
		char            *name_ptr;
		struct sockaddr *addr;
		struct addrinfo *next_ptr;
	};
	]]
else
	ffi.cdef[[
	struct addrinfo {
		int              flags;
		int              family_num;
		int              socktype_num;
		int              protocol_num;
		size_t           addrlen;
		struct sockaddr *addr;
		char            *name_ptr;
		struct addrinfo *next_ptr;
	};
	]]
end

ffi.cdef[[
int getaddrinfo(const char *node, const char *service,
	const struct addrinfo *hints, struct addrinfo **res);
void freeaddrinfo(struct addrinfo *);
]]

local socketargs
do
	local families = {
		inet  = Windows and  2 or Linux and  2,
		inet6 = Windows and 23 or Linux and 10,
		unix  = Linux and 1,
	}
	local family_map = glue.index(families)

	local socket_types = {
		tcp = Windows and 1 or Linux and 1,
		udp = Windows and 2 or Linux and 2,
		raw = Windows and 3 or Linux and 3,
	}
	local socket_type_map = glue.index(socket_types)

	local protocols = {
		ip     = Windows and   0 or Linux and   0,
		icmp   = Windows and   1 or Linux and   1,
		igmp   = Windows and   2 or Linux and   2,
		tcp    = Windows and   6 or Linux and   6,
		udp    = Windows and  17 or Linux and  17,
		raw    = Windows and 255 or Linux and 255,
		ipv6   = Windows and  41 or Linux and  41,
		icmpv6 = Windows and  58 or Linux and  58,
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

	local default_protocols = {
		[socket_types.tcp] = protocols.tcp,
		[socket_types.udp] = protocols.udp,
		[socket_types.raw] = protocols.raw,
	}

	function socketargs(socket_type, family, protocol)
		local st = socket_types[socket_type] or socket_type or 0
		local af = families[family] or family or 0
		local pr = protocols[protocol] or protocol or default_protocols[st] or 0
		return st, af, pr
	end

	local hints = ffi.new'struct addrinfo'
	local addrs = ffi.new'struct addrinfo*[1]'
	local addrinfo_ct = ffi.typeof'struct addrinfo'

	local getaddrinfo_error
	if Windows then
		function getaddrinfo_error()
			return check()
		end
	else
		ffi.cdef'const char *gai_strerror(int ecode);'
		function getaddrinfo_error(err)
			return nil, str(C.gai_strerror(err)), err
		end
	end

	function M.addr(host, port, socket_type, family, protocol, flags)
		if host == nil or host == '*' then host = '0.0.0.0' end --all.
		if host == false then host = nil end --loopback.
		if port == nil then port = 0 end --all.
		if ffi.istype(addrinfo_ct, host) then
			return host, true --pass-through and return "not owned" flag
		elseif type(host) == 'table' then
			local t = host
			host, port, family, socket_type, protocol, flags =
				t.host, t.port, t.family, t.socket_type, t.protocol, t.flags
		end
		ffi.fill(hints, ffi.sizeof(hints))
		hints.socktype_num, hints.family_num, hints.protocol_num
			= socketargs(socket_type, family, protocol)
		hints.flags = glue.bor(flags or 0, flag_bits, true)
		local ret = C.getaddrinfo(host, port and tostring(port), hints, addrs)
		if ret ~= 0 then return getaddrinfo_error(ret) end
		return ffi.gc(addrs[0], C.freeaddrinfo)
	end

	local ai = {}

	function ai:free()
		ffi.gc(self, nil)
		C.freeaddrinfo(self)
	end

	function ai:next(ai)
		local ai = ai and ai.next_ptr or self
		return ai ~= nil and ai or nil
	end

	function ai:addrs()
		return ai.next, self
	end

	function ai:type     () return socket_type_map[self.socktype_num] end
	function ai:family   () return family_map     [self.family_num  ] end
	function ai:protocol () return protocol_map   [self.protocol_num] end
	function ai:name     () return str(self.name_ptr) end
	function ai:tostring () return self.addr:tostring() end

	local sa = {}

	function sa:family () return family_map[self.family_num] end
	function sa:port   () return self.port_bytes[0] * 0x100 + self.port_bytes[1] end

	local AF_INET  = families.inet
	local AF_INET6 = families.inet6
	local AF_UNIX  = families.unix

	function sa:addr()
		local af = self.family_num
		return af == AF_INET and self.addr4
			 or af == AF_INET6 and self.addr6
			 or error'NYI'
	end

	function sa:tostring()
		return self:addr():tostring()..(self:port() ~= 0 and ':'..self:port() or '')
	end

	ffi.metatype('struct sockaddr', {__index = sa})

	local sa_in4 = {}

	function sa_in4:tostring()
		local b = self.ip_bytes
		return string.format('%d.%d.%d.%d', b[0], b[1], b[2], b[3])
	end

	ffi.metatype('struct sockaddr_in', {__index = sa_in4})

	local sa_in6 = {}

	function sa_in6:tostring()
		local b = self.ip_bytes
		--TODO: find first longest sequence of all-zero 16bit components
		--and compress them all into a single '::'.
		return string.format('%x:%x:%x:%x:%x:%x:%x:%x',
			b[ 0]*0x100+b[ 1], b[ 2]*0x100+b[ 3], b[ 4]*0x100+b[ 5], b[ 6]*0x100+b[ 7],
			b[ 8]*0x100+b[ 9], b[10]*0x100+b[11], b[12]*0x100+b[13], b[14]*0x100+b[15])
	end

	ffi.metatype('struct sockaddr_in6', {__index = sa_in6})

	ffi.metatype(addrinfo_ct, {__index = ai})

	function socket:type     () return socket_type_map[self._st] end
	function socket:family   () return family_map     [self._af] end
	function socket:protocol () return protocol_map   [self._pr] end

	function socket:addr(host, port, flags)
		return M.addr(host, port, self._st, self._af, self._pr, addr_flags)
	end

end

--Winsock2 & IOCP ------------------------------------------------------------

if Windows then

ffi.cdef[[

// required types from `winapi.types` ----------------------------------------

typedef unsigned long   ULONG;
typedef unsigned long   DWORD;
typedef int             BOOL;
typedef unsigned short  WORD;
typedef BOOL            *LPBOOL;
typedef int             *LPINT;
typedef DWORD           *LPDWORD;
typedef void            VOID;
typedef VOID            *LPVOID;
typedef const VOID      *LPCVOID;
typedef uint64_t ULONG_PTR, *PULONG_PTR;
typedef VOID            *PVOID;
typedef char            CHAR;
typedef CHAR            *LPSTR;
typedef VOID            *HANDLE;
typedef struct _GUID {
    unsigned long  Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char  Data4[8];
} GUID, *LPGUID;

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

BOOL CancelIoEx(
	HANDLE       hFile,
	LPOVERLAPPED lpOverlapped
);

// Sockets -------------------------------------------------------------------

typedef uintptr_t SOCKET;
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

int getsockopt(
	SOCKET s,
	int    level,
	int    optname,
	char   *optval,
	int    *optlen
);

int setsockopt(
	SOCKET     s,
	int        level,
	int        optname,
	const char *optval,
	int        optlen
);

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

typedef BOOL (*LPFN_ACCEPTEX) (
	SOCKET sListenSocket,
	SOCKET sAcceptSocket,
	PVOID lpOutputBuffer,
	DWORD dwReceiveDataLength,
	DWORD dwLocalAddressLength,
	DWORD dwRemoteAddressLength,
	LPDWORD lpdwBytesReceived,
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
		[10048] = 'address_already_in_use',
	}

	function check(ret, err)
		if ret then return ret end
		local err = err or C.WSAGetLastError()
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

--init winsock library.
do
	local WSADATA = ffi.new'WSADATA'
	assert(check(C.WSAStartup(0x101, WSADATA) == 0))
	assert(WSADATA.wVersion == 0x101)
end

--dynamic binding of winsock functions.
local bind_winsock_func
do
	local IOC_OUT = 0x40000000
	local IOC_IN  = 0x80000000
	local IOC_WS2 = 0x08000000
	local SIO_GET_EXTENSION_FUNCTION_POINTER = bit.bor(IOC_IN, IOC_OUT, IOC_WS2, 6)

	function bind_winsock_func(socket, func_ct, func_guid)
		local cbuf = ffi.new(ffi.typeof('$[1]', ffi.typeof(func_ct)))
		assert(check(C.WSAIoctl(
			socket, SIO_GET_EXTENSION_FUNCTION_POINTER,
			func_guid, ffi.sizeof(func_guid),
			cbuf, ffi.sizeof(cbuf),
			nbuf, nil, nil
		)) == 0)
		assert(cbuf[0] ~= nil)
		return cbuf[0]
	end
end

--Binding ConnectEx() because WSAConnect() doesn't do IOCP.
local function ConnectEx(s, ...)
	ConnectEx = bind_winsock_func(s, 'LPFN_CONNECTEX', ffi.new('GUID',
		0x25a207b9,0xddf3,0x4660,{0x8e,0xe9,0x76,0xe5,0x8c,0x74,0x06,0x3e}))
	return ConnectEx(s, ...)
end

local function AcceptEx(s, ...)
	AcceptEx = bind_winsock_func(s, 'LPFN_ACCEPTEX', ffi.new('GUID',
		{0xb5367df1,0xcbac,0x11cf,{0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}}))
	return AcceptEx(s, ...)
end

do
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
end

do
	local WSA_FLAG_OVERLAPPED = 0x01
	local INVALID_SOCKET = ffi.cast('SOCKET', -1)

	--[[local]] function create_socket(class, socktype, family, protocol)

		family = family or 'inet'
		local st, af, pr = socketargs(socktype, family, protocol)
		assert(st ~= 0, 'socket type required')
		local flags = WSA_FLAG_OVERLAPPED

		local s = C.WSASocketW(af, st, pr, nil, 0, flags)

		if s == INVALID_SOCKET then
			return check()
		end

		local iocp = M.iocp()
		if ffi.C.CreateIoCompletionPort(ffi.cast('HANDLE', s), iocp, 0, 0) ~= iocp then
			return check()
		end

		return wrap_socket(class, s, st, af, pr)
	end
end

do
	local OPT = { --Windows 7 options only
		so_acceptconn         = 0x0002, -- socket has had listen()
		so_broadcast          = 0x0020, -- permit sending of broadcast msgs
		so_bsp_state          = 0x1009, -- get socket 5-tuple state
		so_conditional_accept = 0x3002, -- enable true conditional accept (see msdn)
		so_connect_time       = 0x700C, -- number of seconds a socket has been connected
		so_dontlinger         = bit.bnot(0x0080),
		so_dontroute          = 0x0010, -- just use interface addresses
		so_error              = 0x1007, -- get error status and clear
		so_exclusiveaddruse   = bit.bnot(0x0004), -- disallow local address reuse
		so_keepalive          = 0x0008, -- keep connections alive
		so_linger             = 0x0080, -- linger on close if data present
		so_max_msg_size       = 0x2003, -- maximum message size for UDP
		so_maxdg              = 0x7009,
		so_maxpathdg          = 0x700a,
		so_oobinline          = 0x0100, -- leave received oob data in line
		so_pause_accept       = 0x3003, -- pause accepting new connections
		so_port_scalability   = 0x3006, -- enable port scalability
		so_protocol_info      = 0x2005, -- wsaprotocol_infow structure
		so_randomize_port     = 0x3005, -- randomize assignment of wildcard ports
		so_rcvbuf             = 0x1002, -- receive buffer size
		so_rcvlowat           = 0x1004, -- receive low-water mark
		so_reuseaddr          = 0x0004, -- allow local address reuse
		so_sndbuf             = 0x1001, -- send buffer size
		so_sndlowat           = 0x1003, -- send low-water mark
		so_type               = 0x1008, -- get socket type
		so_update_accept_context  = 0x700b,
		so_update_connect_context = 0x7010,
		so_useloopback        = 0x0040, -- bypass hardware when possible
		tcp_bsdurgent         = 0x7000,
		tcp_expedited_1122  	 = 0x0002,
		tcp_maxrt           	 =      5,
		tcp_nodelay           = 0x0001,
		tcp_timestamps      	 =     10,
	}

	local function get_bool   (buf) return buf.u == 1 end
	local function get_int    (buf) return buf.i end
	local function get_uint   (buf) return buf.u end
	local function get_uint16 (buf) return buf.u16 end

	local buf = ffi.new[[
		union {
			char     c[4];
			uint32_t u;
			uint16_t u16;
			int32_t  i;
		}
	]]

	local function set_bool(v) --BOOL aka DWORD
		buf.u = v
		return buf.c, 4
	end

	local function set_int(v)
		buf.i = v
		return buf.c, 4
	end

	local function set_uint(v)
		buf.u = v
		return buf.c, 4
	end

	local function set_uint16(v)
		buf.u16 = v
		return buf.c, 2
	end

	local function nyi() error'NYI' end
	local get_protocol_info = nyi
	local set_linger = nyi
	local get_csaddr_info = nyi

	local get_opt = {
		so_acceptconn         = get_bool,
		so_broadcast          = get_bool,
		so_bsp_state          = get_csaddr_info,
		so_conditional_accept = get_bool,
		so_connect_time       = get_uint,
		so_dontlinger         = get_bool,
		so_dontroute          = get_bool,
		so_error              = get_uint,
		so_exclusiveaddruse   = get_bool,
		so_keepalive          = get_bool,
		so_linger             = get_linger,
		so_max_msg_size       = get_uint,
		so_maxdg              = get_uint,
		so_maxpathdg          = get_uint,
		so_oobinline          = get_bool,
		so_pause_accept       = get_bool,
		so_port_scalability   = get_bool,
		so_protocol_info      = get_protocol_info,
		so_randomize_port     = get_uint16,
		so_rcvbuf             = get_uint,
		so_rcvlowat           = get_uint,
		so_reuseaddr          = get_bool,
		so_sndbuf             = get_uint,
		so_sndlowat           = get_uint,
		so_type               = get_uint,
		tcp_bsdurgent         = get_bool,
		tcp_expedited_1122  	 = get_bool,
		tcp_maxrt           	 = get_uint,
		tcp_nodelay           = get_bool,
		tcp_timestamps      	 = get_bool,
	}

	local set_opt = {
		so_broadcast          = set_bool,
		so_conditional_accept = set_bool,
		so_dontlinger         = set_bool,
		so_dontroute          = set_bool,
		so_exclusiveaddruse   = set_bool,
		so_keepalive          = set_bool,
		so_linger             = set_linger,
		so_max_msg_size       = set_uint,
		so_oobinline          = set_bool,
		so_pause_accept       = set_bool,
		so_port_scalability   = set_bool,
		so_randomize_port     = set_uint16,
		so_rcvbuf             = set_uint,
		so_rcvlowat           = set_uint,
		so_reuseaddr          = set_bool,
		so_sndbuf             = set_uint,
		so_sndlowat           = set_uint,
		so_update_accept_context  = set_bool,
		so_update_connect_context = set_bool,
		tcp_bsdurgent         = set_bool,
		tcp_expedited_1122  	 = set_bool,
		tcp_maxrt           	 = set_uint,
		tcp_nodelay           = set_bool,
		tcp_timestamps      	 = set_bool,
	}

	local function parse_opt(k)
		local opt = assert(OPT[k], 'invalid socket option')
		local level = k:find('tcp_', 1, true) and 6 or 0xffff
		return opt, level
	end

	function socket:getopt(k)
		local opt, level = parse_opt(k)
		local get = assert(get_opt[k], 'write-only socket option')
		local nbuf = ffi.new('int[1]', 4)
		local ok, err = check(C.getsockopt(self.s, level, opt, buf.c, nbuf))
		if not ok then return nil, err end
		return get(buf, sz)
	end

	function socket:setopt(k, v)
		local opt, level = parse_opt(k)
		local set = assert(set_opt[k], 'read-only socket option')
		local buf, sz = set(v)
		return check(C.setsockopt(self.s, level, opt, buf, sz))
	end

end

function socket:close()
	if self.closed then return true end
	local ok, err, errcode = check(C.closesocket(self.s) == 0)
	if not ok then return ok, err, errcode end
	self.closed = true
	return true
end

local expires_heap = heap.valueheap{
	cmp = function(job1, job2)
		return job1.expires < job2.expires
	end,
	index_key = 'index', --enable O(log n) removal.
}

function M.sleep_until(t)
	expires_heap:push({expires = t, thread = coro.running()})
	wait()
end

local overlapped, free_overlapped
do
	local jobs = {} --{job1, ...}
	local freed = {} --{job_index1, ...}

	local overlapped_ct = ffi.typeof[[
		struct {
			OVERLAPPED overlapped;
			int job_index;
		}
	]]
	local overlapped_ptr_ct = ffi.typeof('$*', overlapped_ct)

	local OVERLAPPED = ffi.typeof'OVERLAPPED'
	local LPOVERLAPPED = ffi.typeof'LPOVERLAPPED'

	function overlapped(socket, done, expires)
		if #freed > 0 then
			local job_index = pop(freed)
			local job = jobs[job_index]
			job.socket = socket
			job.done = done
			job.expires = expires
			local o = ffi.cast(LPOVERLAPPED, job.overlapped)
			ffi.fill(o, ffi.sizeof(OVERLAPPED))
			return o, job
		else
			local job = {s = s, done = done, expires = expires}
			local o = overlapped_ct()
			job.overlapped = o
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

	local WAIT_TIMEOUT = 258
	local ERROR_OPERATION_ABORTED = 995
	local INFINITE = 0xffffffff

	local void_ptr_c = ffi.typeof'void*'

	--[[local]] function poll()

		local job = expires_heap:peek()
		local timeout = job and math.max(0, job.expires - time.clock()) or 1/0

		local timeout_ms = math.max(timeout * 1000, 0)
		--we're going infinite after 0x7fffffff for compat. with Linux.
		if timeout_ms > 0x7fffffff then timeout_ms = INFINITE end

		local ok = ffi.C.GetQueuedCompletionStatus(
			M.iocp(), nbuf, keybuf, obuf, timeout_ms) ~= 0

		local o = obuf[0]
		if o == nil then
			local err = C.WSAGetLastError()
			if err == WAIT_TIMEOUT then
				--cancel all timed-out jobs.
				local t = time.clock()
				while true do
					local job = expires_heap:peek()
					if not job then
						break
					end
					if math.abs(t - job.expires) <= .05 then --arbitrary threshold.
						if job.socket then
							assert(check(ffi.C.CancelIoEx(
								ffi.cast(void_ptr_c, job.socket.s),
								job.overlapped.overlapped)))
						else --sleep
							coro.transfer(job.thread)
						end
						expires_heap:pop()
						job.expires = nil
					else
						--jobs are popped in expire-order so no point looking beyond this.
						break
					end
				end
				--even if we canceled them all, we still have to wait for the OS
				--to abort them. until then we can't recycle the OVERLAPPED structures.
				return true
			else
				return check(nil, err)
			end
		else
			local n = nbuf[0]
			local job = free_overlapped(o)
			if ok then
				if job.expires then
					assert(expires_heap:remove(job))
				end
				coro.transfer(job.thread, job:done(n))
			else
				local err = C.WSAGetLastError()
				if err == ERROR_OPERATION_ABORTED then --canceled
					coro.transfer(job.thread, nil, 'timeout')
				else
					if job.expires then
						assert(expires_heap:remove(job))
					end
					coro.transfer(job.thread, check(nil, err))
				end
			end
			return true
		end
	end
end

do
	local WSA_IO_PENDING = 997

	local function check_timeout(job, ...)
		local ret, err = ...
		if ret == nil and err == 'timeout' then
			job.socket:close()
		end
		return ...
	end

	local function check_pending(ok, job)
		if ok or C.WSAGetLastError() == WSA_IO_PENDING then
			if job.expires then
				expires_heap:push(job)
			end
			job.thread = coro.running()
			return check_timeout(job, wait())
		end
		return check()
	end

	local function return_true()
		return true
	end

	function tcp:connect(host, port, expires, addr_flags)
		if not self._bound then
			--ConnectEx requires binding first.
			local ok, err, errcode = self:bind()
			if not ok then return nil, err, errcode end
		end
		local ai, err, errcode = self:addr(host, port, addr_flags)
		if not ai then return nil, err, errcode end
		local o, job = overlapped(self, return_true, expires)
		local ok = ConnectEx(self.s, ai.addr, ai.addrlen, nil, 0, nil, o) == 1
		if not err then ai:free() end
		return check_pending(ok, job)
	end

	local accept_buf_ct = ffi.typeof[[
		struct {
			struct sockaddr local_addr;
			char reserved[16];
			struct sockaddr remote_addr;
			char reserved[16];
		}
	]]
	local accept_buf = accept_buf_ct()
	local sa_len = ffi.sizeof(accept_buf) / 2
	function tcp:accept(expires)
		local client_s, err, errcode = M.tcp(self._af, self._pr)
		if not client_s then return nil, err, errcode end
		local o, job = overlapped(self, return_true, expires)
		local ok = AcceptEx(self.s, client_s.s, accept_buf, 0, sa_len, sa_len, nbuf, o) == 1
		local ok, err, errcode = check_pending(ok, job)
		if not ok then return nil, err, errcode end
		return client_s, accept_buf.remote_addr, accept_buf.local_addr
	end

	local wsabuf = ffi.new'WSABUF'

	local pchar_t = ffi.typeof'char*'
	local flagsbuf = ffi.new'DWORD[1]'

	local function io_done(job, n)
		if n == 0 then return nil, 'closed' end
		return n
	end

	function tcp:send(buf, len, expires)
		wsabuf.buf = type(buf) == 'string' and ffi.cast(pchar_t, buf) or buf
		wsabuf.len = len or #buf
		local o, job = overlapped(self, io_done, expires)
		local ok = C.WSASend(self.s, wsabuf, 1, nbuf, 0, o, nil) == 0
		return check_pending(ok, job)
	end

	function udp:send(buf, len, host, port, expires, flags, addr_flags)
		local ai, err, errcode = self:addr(host, port, addr_flags)
		if not ai then return nil, err, errcode end
		wsabuf.buf = type(buf) == 'string' and ffi.cast(pchar_t, buf) or buf
		wsabuf.len = len or #buf
		local o, job = overlapped(self, io_done, expires)
		local ok = C.WSASendTo(self.s, wsabuf, 1, nbuf, flags, ai.addr, ai.addrlen, o, nil) == 0
		ai:free()
		return check_pending(ok, job)
	end

	function tcp:recv(buf, len, expires)
		wsabuf.buf = buf
		wsabuf.len = len
		local o, job = overlapped(self, io_done, expires)
		flagsbuf[0] = 0
		local ok = C.WSARecv(self.s, wsabuf, 1, nbuf, flagsbuf, o, nil) == 0
		return check_pending(ok, job)
	end

	function udp:recv(buf, len, host, port, expires, flags, addr_flags)
		local ai, err, errcode = self:addr(host, port, addr_flags)
		if not ai then return nil, err, errcode end
		wsabuf.buf = buf
		wsabuf.len = len
		local o, job = overlapped(self, io_done, expires)
		flagsbuf[0] = flags
		local ok = C.WSARecvFrom(self.s, wsabuf, 1, nbuf, flagsbuf, ai.addr, ai.addrlen, o, nil) == 0
		ai:free()
		return check_pending(ok, job)
	end
end

end --if Windows

--POSIX sockets --------------------------------------------------------------

local register_socket, unregister_socket --fw. decl.

if Linux or OSX then

ffi.cdef[[
typedef int SOCKET;
int socket(int af, int type, int protocol);
int accept(int s, struct sockaddr *addr, int *addrlen);
int accept4(int s, struct sockaddr *addr, int *addrlen, int flags);
int close(int s);
int connect(int s, const struct sockaddr *name, int namelen);
int ioctl(int s, long cmd, unsigned long *argp, ...);
int setsockopt(int sockfd, int level, int optname, const void *optval, unsigned int optlen);
int recv(int s, char *buf, int len, int flags);
int recvfrom(int s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen);
int send(int s, const char *buf, int len, int flags);
int sendto(int s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen);
]]

--error handling.
ffi.cdef'char *strerror(int errnum);'
function check(ret)
	if ret then return ret end
	local err = ffi.errno()
	return ret, str(C.strerror(err)), err
end

local SOCK_NONBLOCK = Linux and tonumber(4000, 8)

--[[local]] function create_socket(class, socktype, family, protocol)
	family = family or 'inet'
	local st, af, pr = socketargs(socktype, family, protocol)
	local s = C.socket(af, bit.bor(st, SOCK_NONBLOCK), pr)
	if s == -1 then
		return check()
	end
	return wrap_socket(class, s, st, af, pr)
end

function socket:close()
	if self.closed then return true end
	local ok, err, errcode = unregister_socket(self)
	if not ok then return ok, err, errcode end
	local ok, err, errcode = check(C.close(self.s) == 0)
	if not ok then return ok, err, errcode end
	self.closed = true
	return true
end

local EWOULDBLOCK = 11 --alias of EAGAIN in Linux
local EINPROGRESS = 115

local recv_expires_heap = heap.valueheap{
	cmp = function(s1, s2)
		return s1.recv_expires < s2.recv_expires
	end,
	index_key = 'index', --enable O(log n) removal.
}

local send_expires_heap = heap.valueheap{
	cmp = function(s1, s2)
		return s1.send_expires < s2.send_expires
	end,
	index_key = 'index', --enable O(log n) removal.
}

function M.sleep_until(t)
	recv_expires_heap:push({recv_expires = t, recv_thread = coro.running()})
	wait()
end

local function make_async(for_writing, f, wait_errno)
	return function(self, expires, ...)
		::again::
		local ret = f(self, ...)
		if ret == 0 then return nil, 'closed' end
		if ret > 0 then return ret end
		if ffi.errno() == wait_errno then
			if for_writing then
				self.send_expires = expires
				if expires then
					send_expires_heap:push(self)
				end
				self.send_thread = coro.running()
			else
				self.recv_expires = expires
				if expires then
					recv_expires_heap:push(self)
				end
				self.recv_thread = coro.running()
			end
			local ok, err = wait()
			if not ok then
				if err == 'timeout' then
					self:close()
				end
				return nil, err
			end
			goto again
		end
		return check()
	end
end

local connect = make_async(true, function(self, ai)
	return C.connect(self.s, ai.addr, ai.addrlen)
end, EINPROGRESS)

function tcp:connect(host, port, expires, addr_flags)
	local ai, err, errcode = self:addr(host, port, addr_flags)
	if not ai then return nil, err, errcode end
	if not self._bound then
		local ok, err, errcode = self:bind()
		if not ok then return nil, err, errcode end
	end
	return connect(self, expires, ai)
end

do
	local nbuf = ffi.new'int[1]'
	local accept_buf = ffi.new'sockaddr'
	local accept_buf_size = ffi.sizeof(accept_buf)

	local tcp_accept = make_async(false, function(self)
		nbuf[0] = accept_buf_size
		return C.accept4(self.s, accept_buf, nbuf, SOCK_NONBLOCK)
	end, EWOULDBLOCK)

	function tcp:accept(expires)
		local s, err, errno = tcp_accept(self, expires)
		if not s then return nil, err, errno end
		local s = wrap_socket(tcp, s, self._st, self._af, self._pr)
		local ok, err, errcode = register_socket(s)
		if not ok then return nil, err, errcode end
		return s, accept_buf
	end
end

local tcp_send = make_async(true, function(self, buf, len, flags)
	return C.send(self.s, buf, len or #buf, flags or 0)
end, EWOULDBLOCK)

function tcp:send(buf, len, expires, flags)
	return tcp_send(self, expires, buf, len, flags)
end

local tcp_recv = make_async(false, function(self, buf, len, flags)
	return C.recv(self.s, buf, len, flags or 0)
end, EWOULDBLOCK)

function tcp:recv(buf, len, expires, flags)
	return tcp_recv(self, expires, buf, len, flags)
end

local udp_send = make_async(true, function(self, buf, len, flags, ai)
	return C.sendto(self.s, buf, len or #buf, flags or 0, ai.addr, ai.addrlen)
end, EWOULDBLOCK)

function udp:send(buf, len, host, port, expires, flags, addr_flags)
	local ai, err, errcode = self:addr(host, port, addr_flags)
	if not ai then return nil, err, errcode end
	return udp_send(self, expires, buf, len, flags, ai)
end

local udp_recv = make_async(false, function(self, buf, len, flags, ai)
	local ret = C.recvfrom(self.s, buf, len, flags or 0, ai.addr, ai.addrlen)
end, EWOULDBLOCK)

function udp:recv(buf, len, host, port, expires, flags, addr_flags)
	local ai, err, errcode = self:addr(host, port, addr_flags)
	if not ai then return nil, err, errcode end
	return udp_recv(self, expires, buf, len, flags, ai)
end

--epoll ----------------------------------------------------------------------

if Linux then

ffi.cdef[[
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

local EPOLLIN  = 0x0001
local EPOLLOUT = 0x0004
local EPOLLERR = 0x0008
local EPOLLET  = 2^31

local EPOLL_CTL_ADD = 1
local EPOLL_CTL_DEL = 2
local EPOLL_CTL_MOD = 3

do
	local epoll_fd
	function M.epoll_fd(shared_epoll_fd, flags)
		if shared_epoll_fd then
			epoll_fd = shared_epoll_fd
		elseif not epoll_fd then
			flags = flags or 0 --TODO: flags
			epoll_fd = C.epoll_create1(flags)
			assert(check(epoll_fd >= 0))
		end
		return epoll_fd
	end
end

do
	local sockets = {} --{s1, ...}
	local free_indices = {} --{i1, ...}

	--[[local]] function register_socket(s)
		local i = pop(free_indices) or #sockets + 1
		s._i = i
		s._e = e
		sockets[i] = s
		local e = ffi.new'struct epoll_event'
		e.data.u32 = i
		e.events = EPOLLIN + EPOLLOUT + EPOLLERR + EPOLLET
		return check(C.epoll_ctl(M.epoll_fd(), EPOLL_CTL_ADD, s.s, e) == 0)
	end

	local ENOENT = 2

	--[[local]] function unregister_socket(s)
		local i = s._i
		if not i then return true end --closing before bind() was called.
		local ok = C.epoll_ctl(M.epoll_fd(), EPOLL_CTL_DEL, s.s, s._e) == 0
		--epoll removed the fd if connection was closed so ENOENT is normal.
		if not ok and ffi.errno() ~= ENOENT then
			return check()
		end
		sockets[i] = false
		push(free_indices, i)
		return true
	end

	local function resume(socket, e, event, for_writing)
		if bit.band(e, event) ~= 0 then --read
			local thread
			if for_writing then
				thread = socket.send_thread
			else
				thread = socket.recv_thread
			end
			if not thread then return end --misfire.
			if for_writing then
				if socket.send_expires then
					assert(send_expires_heap:remove(socket))
					socket.send_expires = nil
				end
				socket.send_thread = nil
			else
				if socket.recv_expires then
					assert(recv_expires_heap:remove(socket))
					socket.recv_expires = nil
				end
				socket.recv_thread = nil
			end
			coro.transfer(thread, true)
		end
	end

	local function check_heap(heap, EXPIRES, THREAD, t)
		while true do
			local socket = heap:peek()
			if not socket then
				break
			end
			if math.abs(t - socket[EXPIRES]) <= .05 then --arbitrary threshold.
				assert(heap:pop())
				socket[EXPIRES] = nil
				local thread = socket[THREAD]
				socket[THREAD] = nil
				coro.transfer(thread, nil, 'timeout')
			else
				--socket are popped in expire-order so no point looking beyond this.
				break
			end
		end
	end

	local maxevents = 1
	local events = ffi.new('struct epoll_event[?]', maxevents)

	--[[local]] function poll()

		local ss = send_expires_heap:peek()
		local rs = recv_expires_heap:peek()
		local sx = ss and ss.send_expires
		local rx = rs and rs.recv_expires
		local expires = math.min(sx or 1/0, rx or 1/0)
		local timeout = expires < 1/0 and math.max(0, expires - time.clock()) or 1/0

		local timeout_ms = math.max(timeout * 1000, 0)
		if timeout_ms > 0x7fffffff then timeout_ms = -1 end --infinite

		local n = C.epoll_wait(M.epoll_fd(), events, maxevents, timeout_ms)
		if n > 0 then
			for i = 0, n-1 do
				local socket = sockets[events[i].data.u32]
				local e = events[i].events
				resume(socket, e, EPOLLIN , false)
				resume(socket, e, EPOLLOUT, true)
			end
			return true
		elseif n == 0 then
			--handle timed-out ops.
			local t = time.clock()
			check_heap(send_expires_heap, 'send_expires', 'send_thread', t)
			check_heap(recv_expires_heap, 'recv_expires', 'recv_thread', t)
			return true
		else
			return check()
		end
	end
end

end --if Linux

--kqueue ---------------------------------------------------------------------

if OSX then

ffi.cdef[[
int kqueue(void);
int kevent(int kq, const struct kevent *changelist, int nchanges,
	struct kevent *eventlist, int nevents,
	const struct timespec *timeout);
// EV_SET(&kev, ident, filter, flags, fflags, data, udata);
]]

end --if OSX

end --if Linux or OSX

--shutodnw() -----------------------------------------------------------------

ffi.cdef[[
int shutdown(SOCKET s, int how);
]]

function tcp:shutdown(which)
	return check(ffi.C.shutdown(self.s,
		   which == 'r' and 0
		or which == 'w' and 1
		or (not which or which == 'rw' and 2)))
end

--bind() ---------------------------------------------------------------------

ffi.cdef[[
int bind(SOCKET s, const sockaddr*, int namelen);
]]

function socket:bind(host, port, addr_flags)
	assert(not self._bound)
	local ai, err, errcode = self:addr(host, port, addr_flags)
	if not ai then return nil, err, errcode end
	local ok = C.bind(self.s, ai.addr, ai.addrlen) == 0
	if not err then ai:free() end
	if not ok then return check() end
	self._bound = true
	--epoll_ctl() must be called after bind() for some reason.
	if register_socket then
		return register_socket(self)
	end
	return true
end

--listen() -------------------------------------------------------------------

ffi.cdef[[
int listen(SOCKET s, int backlog);
]]

function tcp:listen(backlog, host, port, addr_flags)
	if type(backlog) ~= 'number' then
		backlog, host, port = 1/0, backlog, host
	end
	if not self._bound then
		local ok, err, errcode = self:bind(host, port, addr_flags)
		if not ok then
			return nil, err, errcode
		end
	end
	backlog = glue.clamp(backlog or 1/0, 0, 0x7fffffff)
	local ok = C.listen(self.s, backlog) == 0
	if not ok then return check() end
	return true
end

--hi-level API ---------------------------------------------------------------

--[[local]] function wrap_socket(class, s, st, af, pr)
	local s = {s = s, __index = class, _st = st, _af = af, _pr = pr}
	return setmetatable(s, s)
end
function M.tcp(...) return create_socket(tcp, 'tcp', ...) end
function M.udp(...) return create_socket(udp, 'udp', ...) end
function M.raw(...) return create_socket(raw, 'raw', ...) end

glue.update(tcp, socket)
glue.update(udp, socket)
glue.update(raw, socket)

--coroutine-based scheduler --------------------------------------------------

M.cosafewrap = coro.safewrap
M.thread = coro.running

local poll_thread
local wait_count = 0

do
	local function pass(...)
		wait_count = wait_count - 1
		return ...
	end
	--[[local]] function wait()
		assert(coro.running() ~= poll_thread, 'trying to I/O from the main thread')
		wait_count = wait_count + 1
		return pass(coro.transfer(poll_thread))
	end
end

function M.poll()
	if wait_count == 0 then
		return nil, 'empty'
	end
	return poll()
end

function M.newthread(handler, ...)
	--wrap handler so that it terminates in current poll_thread.
	local thread = coro.create(function(...)
		local ok, err = glue.pcall(handler, ...) --last chance to get stacktrace.
		if not ok then error(err, 2) end
		coro.transfer(poll_thread)
	end)
	M.resume(thread, ...)
	return thread
end

function M.suspend(...)
	return coro.transfer(poll_thread, ...)
end

function M.sleep(s)
	return M.sleep_until(time.clock() + s)
end

do
	local function pass(real_poll_thread, ...)
		poll_thread = real_poll_thread
		return ...
	end
	function M.resume(thread, ...)
		local real_poll_thread = poll_thread
		--change poll_thread temporarily so that we get back here
		--from suspend() or from I/O.
		poll_thread = coro.running()
		return pass(real_poll_thread, coro.transfer(thread, ...))
	end
end

local stop = false
function M.stop() stop = true end
function M.start()
	poll_thread = coro.running()
	repeat
		local ret, err, errcode = M.poll()
		if not ret then
			if err == 'empty' then
				M.stop()
			else
				return ret, err, errcode
			end
		end
	until stop
	return true
end

return M
