/** 
 @file  win32.c
 @brief ENet Win32 system specific functions
*/
#ifdef _WIN32

#define ENET_BUILDING_LIB 1
#include "enet/enet.h"
#include <windows.h>
#include <mmsystem.h>

static enet_uint32 timeBase = 0;

/**
    @retval > 0 if host already bound to (the same) intrHostData
	@retval 0 otherwise
*/
static int
enet_intr_host_data_already_bound (ENetHost * host, struct ENetIntrHostData * intrHostData)
{
	if (host -> intrHostData == intrHostData)
		return 1;

	return 0;
}

static int
enet_intr_token_already_bound (ENetHost * host, struct ENetIntrToken * intrToken)
{
	if (host -> intrToken == intrToken)
		return 1;

	return 0;
}

static int
enet_intr_token_disabled (struct ENetIntrToken * intrToken)
{
	return ! intrToken -> intrHostData;
}

/** Perform similar role as poll(2).

	@retval > 0 if an event occurred within the specified time limit.
	            specifically: 1 on interrupt and 2 on socket event.
	@retval 0 if no event occurred
	@retval < 0 on failure
*/
static int
enet_intr_host_data_helper_event_wait (ENetHost * host, enet_uint32 timeoutMsec)
{
	struct ENetIntrHostDataWin32 * data = (struct ENetIntrHostDataWin32 *) host -> intrHostData;

	/* FIXME: can use both WSACreateEvent and CreateEvent events
	*    in WSAWaitForMultipleEvents but is the type WSAEVENT or HANDLE? */
	WSAEVENT EventArray[2] = { 0 };

	DWORD ret = 0;
	DWORD indexSignaled = 0;

	/* should not happen */
	if (host -> intrHostData -> type != ENET_INTR_DATA_TYPE_WIN32)
		return -1;

	EventArray[0] = data -> hEventInterrupt;
	EventArray[1] = data -> EventSocket;

	/* FIXME: timeout handling? special negative timeout value (as poll(2))? set fAlertable for alertable wait? */
	ret = WSAWaitForMultipleEvents (2, EventArray, FALSE, timeoutMsec, FALSE);

	if (ret == WSA_WAIT_TIMEOUT)
		return 0;

	indexSignaled = ret - WSA_WAIT_EVENT_0;

	if (indexSignaled == 0)
		return 1;
	else
		return 2;
}

static int
enet_intr_host_data_helper_event_enum (ENetHost * host, enet_uint32 * condition)
{
	struct ENetIntrHostDataWin32 * data = (struct ENetIntrHostDataWin32 *) host -> intrHostData;

	WSAEVENT EventSocket = data -> EventSocket;

	WSANETWORKEVENTS events = { 0 };

	enet_uint32 newCondition = 0;

	/* should not happen */
	if (host -> intrHostData -> type != ENET_INTR_DATA_TYPE_WIN32)
		return -1;

	if (WSAEnumNetworkEvents (host -> socket, EventSocket, &events))
		return -1;

	newCondition = ENET_SOCKET_WAIT_NONE;

	if (* condition & ENET_SOCKET_WAIT_RECEIVE
		&& events.lNetworkEvents & FD_READ)
	{
		newCondition |= ENET_SOCKET_WAIT_RECEIVE;
	}

	/* only checking for read (FD_READ) - writes are shimmed (always assumed yes) */
	if (* condition & ENET_SOCKET_WAIT_SEND
		&& 1 /* dummy */)
	{
		newCondition |= ENET_SOCKET_WAIT_SEND;
	}

	* condition = newCondition;

	return 0;
}

/** Create both events (for Interruption and for Socket activity).
*/
static int
enet_intr_host_data_helper_make_event (ENetSocket socket, WSAEVENT * outputWSAEventSocket, HANDLE * outputHWSAEventInterrupt)
{
	if ((* outputWSAEventSocket = WSACreateEvent ()) == WSA_INVALID_EVENT)
		return -1;

	/* https://msdn.microsoft.com/en-us/library/windows/desktop/ms741561(v=vs.85).aspx 
	*    WSACreateEvent MSDN remarks suggest CreateEvent for creating an auto-reset event. */

	if ((* outputHWSAEventInterrupt = CreateEvent (NULL, FALSE, FALSE, NULL)) == NULL)
		return -1;

	/* FD_READ alone or also for example FD_WRITE, FD_CLOSE ? */
	/* note: FD_WRITE is probably a mistake - (almost) always triggered? shimmed instead. */
	if (WSAEventSelect (socket, * outputWSAEventSocket, FD_READ))
		return -1;

	return 0;
}

static
enet_intr_host_data_helper_free_event (WSAEVENT * outputWSAEventSocket, HANDLE * outputHWSAEventInterrupt)
{
	if (! WSACloseEvent (outputWSAEventSocket))
		return -1;

	if (! CloseHandle (outputHWSAEventInterrupt))
		return -1;

	return 0;
}

static int
enet_intr_host_socket_wait_interruptible_win32 (ENetHost * host, enet_uint32 * condition, enet_uint32 timeout, struct ENetIntrHostData * intrHostData, struct ENetIntrToken * intrToken, struct ENetIntr * intr)
{
	int retSocketWait = 0;

	if (! enet_intr_host_data_already_bound (host, intrHostData))
		return -1;

	if (intrToken -> cb_token_bind (intrToken, host))
		return -1;

	intr -> cb_last_chance (intrToken);

	retSocketWait = enet_intr_host_data_helper_event_wait (host, timeout);

	if (retSocketWait < 0)
		return -1;

	if (retSocketWait == 0)
	{
		* condition = ENET_SOCKET_WAIT_NONE;

		return 0;
	}

	if (retSocketWait == 1)
	{
		* condition = ENET_SOCKET_WAIT_INTERRUPT;

		return 0;
	}

	/* should not happen */
	if (retSocketWait != 2)
		return -1;

	if (enet_intr_host_data_helper_event_enum (host, condition))
		return -1;

	return 0;
}

static int
enet_intr_host_bind_win32 (ENetHost * host, struct ENetIntrHostData * intrHostData)
{
	if (enet_intr_host_data_already_bound (host, intrHostData))
		return 0;

	if (intrHostData -> type != ENET_INTR_DATA_TYPE_WIN32)
		return -1;

	/* would overwrite existing */
	if (host -> intrHostData)
		return -1;

	host -> intrHostData = intrHostData;

	return 0;
}

static int
enet_intr_host_destroy_win32 (struct _ENetHost * host)
{
	struct ENetIntrHostDataWin32 * pData = (struct ENetIntrHostDataWin32 *) host -> intrHostData;

	if (! pData)
		return 0;

	if (pData -> base.type != ENET_INTR_DATA_TYPE_WIN32)
		return -1;

	if (enet_intr_host_data_helper_free_event (& pData -> EventSocket, & pData -> hEventInterrupt))
		return -1;

	enet_free (pData);

	return 0;
}

struct ENetIntrHostData *
enet_intr_host_create_and_bind_win32 (struct _ENetHost * host)
{
	struct ENetIntrHostDataWin32 *pData = (struct ENetIntrHostDataWin32 *) enet_malloc (sizeof(struct ENetIntrHostDataWin32));

	if (!pData)
		return NULL;

	pData -> base.type = ENET_INTR_DATA_TYPE_WIN32;

	pData -> base.cb_host_create = enet_intr_host_create_and_bind_win32;
	pData -> base.cb_host_destroy = enet_intr_host_destroy_win32;
	pData -> base.cb_host_bind = enet_intr_host_bind_win32;
	pData -> base.cb_host_socket_wait_interruptible = enet_intr_host_socket_wait_interruptible_win32;

	/* initialize events */

	pData -> EventSocket = WSA_INVALID_EVENT;
	pData -> hEventInterrupt = NULL;

	if (enet_intr_host_data_helper_make_event (host -> socket, & pData -> EventSocket, & pData -> hEventInterrupt))
		return NULL;

	/* bind to host */

	if (pData -> base.cb_host_bind (host, (struct ENetIntrHostData *) pData))
		return NULL;

	return & pData -> base;
}

static int
enet_intr_token_destroy_win32 (struct ENetIntrToken * gentoken)
{
	struct ENetIntrTokenWin32 * pToken = (struct ENetIntrTokenWin32 *) gentoken;

	if (gentoken -> type != ENET_INTR_DATA_TYPE_WIN32)
		return -1;

	DeleteCriticalSection (& pToken -> mutexData);

	enet_free (pToken);

	return 0;
}

/** Blindly overwrite token with new host (unless already bound to it).
    If token is already bound to a host it will not be unbound
	from the old host or anything.
    
	Calls to this function are designed to be triggered from the ENetHost host.
    - Host has to ensure read access to intrHostData field is safe
	(sequencing, no conflicting writes, field not yet destroyed, etc).
	- Host has to ensure write access to intrToken field is safe.
	By field it is meant the pointer only (not accesses within the pointed-to struct).
	Ensuring both seemingly should not require locking at the host side.
	(ex since calls are only triggered from the host.
*/
static int
enet_intr_token_bind_win32 (struct ENetIntrToken * intrToken, ENetHost * host)
{
	int ret = 0;

	LPCRITICAL_SECTION pMutexData = NULL;

	struct ENetIntrTokenWin32 * pToken = (struct ENetIntrTokenWin32 *) intrToken;

	if (intrToken -> type != ENET_INTR_DATA_TYPE_WIN32)
		{ ret = -1; goto clean; }

	/* FIXME: can this check actually be performed outside the mutex lock ?
	*    probably not: host 'notifies' token of host destruction by disabling the token.
	*                  need to check for disabled state (which must be inside mutex lock) before this check.
	*                  releasing the mutex lock after disabled state check will race against host destruction. */
	if (enet_intr_token_already_bound (host, intrToken))
		{ ret = 0; goto clean; };

	EnterCriticalSection (& pToken -> mutexData);
	/* take unlock responsibility */
	pMutexData = & pToken -> mutexData;

	/* bind on token side */
	pToken -> base.intrHostData = host -> intrHostData;

	/* would overwrite existing */
	if (host -> intrToken)
		{ ret = -1; goto clean; };

	/* bind on host side */
	host -> intrToken = (struct ENetIntrToken *) pToken;

clean:
	if (pMutexData)
		LeaveCriticalSection (pMutexData);

	return ret;
}

static int
enet_intr_token_unbind_win32 (struct ENetIntrToken * gentoken, ENetHost * host)
{
	int ret = 0;

	LPCRITICAL_SECTION pMutexData = NULL;

	struct ENetIntrTokenWin32 * pToken = (struct ENetIntrTokenWin32 *) gentoken;

	/* paranoia */
	if (gentoken -> type != ENET_INTR_DATA_TYPE_WIN32)
		{ ret = -1; goto clean; }

	EnterCriticalSection (& pToken -> mutexData);
	/* take unlock responsibility */
	pMutexData = & pToken -> mutexData;

	if (enet_intr_token_disabled (& pToken -> base))
		{ ret = 0; goto clean; };

	/* not bound to passed host? */
	if (pToken -> base.intrHostData != host -> intrHostData)
		{ ret = -1; goto clean; };

	pToken -> base.intrHostData = NULL;

clean:
	if (pMutexData)
		LeaveCriticalSection (pMutexData);

	return ret;
}

static int
enet_intr_token_interrupt_win32 (struct ENetIntrToken * gentoken)
{
	int ret = 0;

	LPCRITICAL_SECTION pMutexData = NULL;

	struct ENetIntrTokenWin32 * pToken = (struct ENetIntrTokenWin32 *) gentoken;

	/* paranoia */
	if (gentoken -> type != ENET_INTR_DATA_TYPE_WIN32)
		{ ret = -1; goto clean; };

	EnterCriticalSection (& pToken -> mutexData);
	/* take unlock responsibility */
	pMutexData = & pToken -> mutexData;

	if (enet_intr_token_disabled (& pToken -> base))
		{ ret = 0; goto clean; };

	/* paranoia */
	if (pToken -> base.intrHostData -> type != ENET_INTR_DATA_TYPE_WIN32)
		{ ret = -1; goto clean; };

	if (! SetEvent (((struct ENetIntrHostDataWin32 *) pToken -> base.intrHostData) -> hEventInterrupt))
		{ ret = -1; goto clean; };

clean:
	if (pMutexData)
		LeaveCriticalSection (pMutexData);

	return ret;
}

struct ENetIntrToken *
enet_intr_token_create_win32 (void)
{
	struct ENetIntrTokenWin32 * pToken = (struct ENetIntrTokenWin32 *) enet_malloc (sizeof (struct ENetIntrTokenWin32));

	if (!pToken)
		return NULL;

	pToken -> base.type = ENET_INTR_DATA_TYPE_WIN32;

	pToken -> base.intrHostData = NULL;

	pToken -> base.cb_token_create = enet_intr_token_create_win32;
	pToken -> base.cb_token_destroy = enet_intr_token_destroy_win32;
	pToken -> base.cb_token_bind = enet_intr_token_bind_win32;
	pToken -> base.cb_token_unbind = enet_intr_token_bind_win32;
	pToken -> base.cb_token_interrupt = enet_intr_token_interrupt_win32;

	InitializeCriticalSection (& pToken -> mutexData);

	EnterCriticalSection (& pToken -> mutexData);
	LeaveCriticalSection (& pToken -> mutexData);

	return & pToken -> base;
}

int
enet_initialize (void)
{
    WORD versionRequested = MAKEWORD (1, 1);
    WSADATA wsaData;
   
    if (WSAStartup (versionRequested, & wsaData))
       return -1;

    if (LOBYTE (wsaData.wVersion) != 1||
        HIBYTE (wsaData.wVersion) != 1)
    {
       WSACleanup ();
       
       return -1;
    }

    timeBeginPeriod (1);

    return 0;
}

void
enet_deinitialize (void)
{
    timeEndPeriod (1);

    WSACleanup ();
}

enet_uint32
enet_host_random_seed (void)
{
    return (enet_uint32) timeGetTime ();
}

enet_uint32
enet_time_get (void)
{
    return (enet_uint32) timeGetTime () - timeBase;
}

void
enet_time_set (enet_uint32 newTimeBase)
{
    timeBase = (enet_uint32) timeGetTime () - newTimeBase;
}

int
enet_address_set_host (ENetAddress * address, const char * name)
{
    struct hostent * hostEntry;

    hostEntry = gethostbyname (name);
    if (hostEntry == NULL ||
        hostEntry -> h_addrtype != AF_INET)
    {
        unsigned long host = inet_addr (name);
        if (host == INADDR_NONE)
            return -1;
        address -> host = host;
        return 0;
    }

    address -> host = * (enet_uint32 *) hostEntry -> h_addr_list [0];

    return 0;
}

int
enet_address_get_host_ip (const ENetAddress * address, char * name, size_t nameLength)
{
    char * addr = inet_ntoa (* (struct in_addr *) & address -> host);
    if (addr == NULL)
        return -1;
    else
    {
        size_t addrLen = strlen(addr);
        if (addrLen >= nameLength)
          return -1;
        memcpy (name, addr, addrLen + 1);
    }
    return 0;
}

int
enet_address_get_host (const ENetAddress * address, char * name, size_t nameLength)
{
    struct in_addr in;
    struct hostent * hostEntry;
 
    in.s_addr = address -> host;
    
    hostEntry = gethostbyaddr ((char *) & in, sizeof (struct in_addr), AF_INET);
    if (hostEntry == NULL)
      return enet_address_get_host_ip (address, name, nameLength);
    else
    {
       size_t hostLen = strlen (hostEntry -> h_name);
       if (hostLen >= nameLength)
         return -1;
       memcpy (name, hostEntry -> h_name, hostLen + 1);
    }

    return 0;
}

int
enet_socket_bind (ENetSocket socket, const ENetAddress * address)
{
    struct sockaddr_in sin;

    memset (& sin, 0, sizeof (struct sockaddr_in));

    sin.sin_family = AF_INET;

    if (address != NULL)
    {
       sin.sin_port = ENET_HOST_TO_NET_16 (address -> port);
       sin.sin_addr.s_addr = address -> host;
    }
    else
    {
       sin.sin_port = 0;
       sin.sin_addr.s_addr = INADDR_ANY;
    }

    return bind (socket,
                 (struct sockaddr *) & sin,
                 sizeof (struct sockaddr_in)) == SOCKET_ERROR ? -1 : 0;
}

int
enet_socket_get_address (ENetSocket socket, ENetAddress * address)
{
    struct sockaddr_in sin;
    int sinLength = sizeof (struct sockaddr_in);

    if (getsockname (socket, (struct sockaddr *) & sin, & sinLength) == -1)
      return -1;

    address -> host = (enet_uint32) sin.sin_addr.s_addr;
    address -> port = ENET_NET_TO_HOST_16 (sin.sin_port);

    return 0;
}

int
enet_socket_listen (ENetSocket socket, int backlog)
{
    return listen (socket, backlog < 0 ? SOMAXCONN : backlog) == SOCKET_ERROR ? -1 : 0;
}

ENetSocket
enet_socket_create (ENetSocketType type)
{
    return socket (PF_INET, type == ENET_SOCKET_TYPE_DATAGRAM ? SOCK_DGRAM : SOCK_STREAM, 0);
}

int
enet_socket_set_option (ENetSocket socket, ENetSocketOption option, int value)
{
    int result = SOCKET_ERROR;
    switch (option)
    {
        case ENET_SOCKOPT_NONBLOCK:
        {
            u_long nonBlocking = (u_long) value;
            result = ioctlsocket (socket, FIONBIO, & nonBlocking);
            break;
        }

        case ENET_SOCKOPT_BROADCAST:
            result = setsockopt (socket, SOL_SOCKET, SO_BROADCAST, (char *) & value, sizeof (int));
            break;

        case ENET_SOCKOPT_REUSEADDR:
            result = setsockopt (socket, SOL_SOCKET, SO_REUSEADDR, (char *) & value, sizeof (int));
            break;

        case ENET_SOCKOPT_RCVBUF:
            result = setsockopt (socket, SOL_SOCKET, SO_RCVBUF, (char *) & value, sizeof (int));
            break;

        case ENET_SOCKOPT_SNDBUF:
            result = setsockopt (socket, SOL_SOCKET, SO_SNDBUF, (char *) & value, sizeof (int));
            break;

        case ENET_SOCKOPT_RCVTIMEO:
            result = setsockopt (socket, SOL_SOCKET, SO_RCVTIMEO, (char *) & value, sizeof (int));
            break;

        case ENET_SOCKOPT_SNDTIMEO:
            result = setsockopt (socket, SOL_SOCKET, SO_SNDTIMEO, (char *) & value, sizeof (int));
            break;

        case ENET_SOCKOPT_NODELAY:
            result = setsockopt (socket, IPPROTO_TCP, TCP_NODELAY, (char *) & value, sizeof (int));
            break;

        default:
            break;
    }
    return result == SOCKET_ERROR ? -1 : 0;
}

int
enet_socket_get_option (ENetSocket socket, ENetSocketOption option, int * value)
{
    int result = SOCKET_ERROR, len;
    switch (option)
    {
        case ENET_SOCKOPT_ERROR:
            len = sizeof(int);
            result = getsockopt (socket, SOL_SOCKET, SO_ERROR, (char *) value, & len);
            break;

        default:
            break;
    }
    return result == SOCKET_ERROR ? -1 : 0;
}

int
enet_socket_connect (ENetSocket socket, const ENetAddress * address)
{
    struct sockaddr_in sin;
    int result;

    memset (& sin, 0, sizeof (struct sockaddr_in));

    sin.sin_family = AF_INET;
    sin.sin_port = ENET_HOST_TO_NET_16 (address -> port);
    sin.sin_addr.s_addr = address -> host;

    result = connect (socket, (struct sockaddr *) & sin, sizeof (struct sockaddr_in));
    if (result == SOCKET_ERROR && WSAGetLastError () != WSAEWOULDBLOCK)
      return -1;

    return 0;
}

ENetSocket
enet_socket_accept (ENetSocket socket, ENetAddress * address)
{
    SOCKET result;
    struct sockaddr_in sin;
    int sinLength = sizeof (struct sockaddr_in);

    result = accept (socket, 
                     address != NULL ? (struct sockaddr *) & sin : NULL, 
                     address != NULL ? & sinLength : NULL);

    if (result == INVALID_SOCKET)
      return ENET_SOCKET_NULL;

    if (address != NULL)
    {
        address -> host = (enet_uint32) sin.sin_addr.s_addr;
        address -> port = ENET_NET_TO_HOST_16 (sin.sin_port);
    }

    return result;
}

int
enet_socket_shutdown (ENetSocket socket, ENetSocketShutdown how)
{
    return shutdown (socket, (int) how) == SOCKET_ERROR ? -1 : 0;
}

void
enet_socket_destroy (ENetSocket socket)
{
    if (socket != INVALID_SOCKET)
      closesocket (socket);
}

int
enet_socket_send (ENetSocket socket,
                  const ENetAddress * address,
                  const ENetBuffer * buffers,
                  size_t bufferCount)
{
    struct sockaddr_in sin;
    DWORD sentLength;

    if (address != NULL)
    {
        memset (& sin, 0, sizeof (struct sockaddr_in));

        sin.sin_family = AF_INET;
        sin.sin_port = ENET_HOST_TO_NET_16 (address -> port);
        sin.sin_addr.s_addr = address -> host;
    }

    if (WSASendTo (socket, 
                   (LPWSABUF) buffers,
                   (DWORD) bufferCount,
                   & sentLength,
                   0,
                   address != NULL ? (struct sockaddr *) & sin : NULL,
                   address != NULL ? sizeof (struct sockaddr_in) : 0,
                   NULL,
                   NULL) == SOCKET_ERROR)
    {
       if (WSAGetLastError () == WSAEWOULDBLOCK)
         return 0;

       return -1;
    }

    return (int) sentLength;
}

int
enet_socket_receive (ENetSocket socket,
                     ENetAddress * address,
                     ENetBuffer * buffers,
                     size_t bufferCount)
{
    INT sinLength = sizeof (struct sockaddr_in);
    DWORD flags = 0,
          recvLength;
    struct sockaddr_in sin;

    if (WSARecvFrom (socket,
                     (LPWSABUF) buffers,
                     (DWORD) bufferCount,
                     & recvLength,
                     & flags,
                     address != NULL ? (struct sockaddr *) & sin : NULL,
                     address != NULL ? & sinLength : NULL,
                     NULL,
                     NULL) == SOCKET_ERROR)
    {
       switch (WSAGetLastError ())
       {
       case WSAEWOULDBLOCK:
       case WSAECONNRESET:
          return 0;
       }

       return -1;
    }

    if (flags & MSG_PARTIAL)
      return -1;

    if (address != NULL)
    {
        address -> host = (enet_uint32) sin.sin_addr.s_addr;
        address -> port = ENET_NET_TO_HOST_16 (sin.sin_port);
    }

    return (int) recvLength;
}

int
enet_socketset_select (ENetSocket maxSocket, ENetSocketSet * readSet, ENetSocketSet * writeSet, enet_uint32 timeout)
{
    struct timeval timeVal;

    timeVal.tv_sec = timeout / 1000;
    timeVal.tv_usec = (timeout % 1000) * 1000;

    return select (maxSocket + 1, readSet, writeSet, NULL, & timeVal);
}

int
enet_socket_wait (ENetSocket socket, enet_uint32 * condition, enet_uint32 timeout)
{
    fd_set readSet, writeSet;
    struct timeval timeVal;
    int selectCount;
    
    timeVal.tv_sec = timeout / 1000;
    timeVal.tv_usec = (timeout % 1000) * 1000;
    
    FD_ZERO (& readSet);
    FD_ZERO (& writeSet);

    if (* condition & ENET_SOCKET_WAIT_SEND)
      FD_SET (socket, & writeSet);

    if (* condition & ENET_SOCKET_WAIT_RECEIVE)
      FD_SET (socket, & readSet);

    selectCount = select (socket + 1, & readSet, & writeSet, NULL, & timeVal);

    if (selectCount < 0)
      return -1;

    * condition = ENET_SOCKET_WAIT_NONE;

    if (selectCount == 0)
      return 0;

    if (FD_ISSET (socket, & writeSet))
      * condition |= ENET_SOCKET_WAIT_SEND;
    
    if (FD_ISSET (socket, & readSet))
      * condition |= ENET_SOCKET_WAIT_RECEIVE;

    return 0;
}

#endif
