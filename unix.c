/** 
 @file  unix.c
 @brief ENet Unix system specific functions
*/
#ifndef _WIN32

#define _GNU_SOURCE  // for ppoll

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>

#define ENET_BUILDING_LIB 1
#include "enet/enet.h"

#ifdef __APPLE__
#ifdef HAS_POLL
#undef HAS_POLL
#endif
#ifndef HAS_FCNTL
#define HAS_FCNTL 1
#endif
#ifndef HAS_INET_PTON
#define HAS_INET_PTON 1
#endif
#ifndef HAS_INET_NTOP
#define HAS_INET_NTOP 1
#endif
#ifndef HAS_MSGHDR_FLAGS
#define HAS_MSGHDR_FLAGS 1
#endif
#ifndef HAS_SOCKLEN_T
#define HAS_SOCKLEN_T 1
#endif
#ifndef HAS_GETADDRINFO
#define HAS_GETADDRINFO 1
#endif
#ifndef HAS_GETNAMEINFO
#define HAS_GETNAMEINFO 1
#endif
#endif

#ifdef HAS_FCNTL
#include <fcntl.h>
#endif

#ifdef HAS_POLL
#include <sys/poll.h>
#endif

#ifndef HAS_SOCKLEN_T
typedef int socklen_t;
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static enet_uint32 timeBase = 0;

/** FIXME: duplicate
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

/** FIXME: duplicate */
static int
enet_intr_token_already_bound (ENetHost * host, struct ENetIntrToken * intrToken)
{
	if (host -> intrToken == intrToken)
		return 1;

	return 0;
}

/** FIXME: duplicate */
static int
enet_intr_token_disabled (struct ENetIntrToken * intrToken)
{
	return ! intrToken -> intrHostData;
}

static int
enet_intr_host_token_bind(ENetHost * host, struct ENetIntrToken * intrToken)
{
	/* early exit */
	if (enet_intr_token_already_bound (host, intrToken))
		return 0;

	if (intrToken -> type != ENET_INTR_DATA_TYPE_UNIX)
		return -1;

	if (intrToken -> cb_token_bind (intrToken, host))
		return -1;

	host -> intrToken = intrToken;

	return 0;
}

static int
enet_intr_host_socket_wait_interruptible_unix (ENetHost * host, enet_uint32 * condition, enet_uint32 timeout, struct ENetIntrHostData * intrHostData, struct ENetIntrToken * intrToken, struct ENetIntr * intr)
{
#ifndef HAS_POLL
#  error no poll - port some time
#endif /* HAS_POLL */

	if (! enet_intr_host_data_already_bound (host, intrHostData))
		return -1;

	if (enet_intr_host_token_bind (host, intrToken))
		return -1;

	struct pollfd pollSocket;
	int pollCount;

	sigset_t oldSigSet = {};
	sigset_t newSigSet = {};

	struct timespec timespecTimeout = {};
	struct timespec * ppollTimespecTimeout = NULL;

	if (((int) timeout) < 0)
	{
		ppollTimespecTimeout = NULL;
	}
	else
	{
		timespecTimeout.tv_sec = timeout / 1000;
		timespecTimeout.tv_nsec = (timeout % 1000) * 1000000;
		ppollTimespecTimeout = & timespecTimeout;
	}


	pollSocket.fd = host -> socket;
	pollSocket.events = 0;

	if (* condition & ENET_SOCKET_WAIT_SEND)
		pollSocket.events |= POLLOUT;

	if (* condition & ENET_SOCKET_WAIT_RECEIVE)
		pollSocket.events |= POLLIN;

	/* BEGIN - magic ppoll dance */

	if (sigfillset (&newSigSet))
		return -1;

	if (pthread_sigmask (SIG_SETMASK, & newSigSet, & oldSigSet))
		return -1;

	intr->cb_last_chance (intrToken);

	pollCount = ppoll (& pollSocket, 1, ppollTimespecTimeout, & oldSigSet);

	if (pthread_sigmask (SIG_SETMASK, & oldSigSet, NULL))
		return -1;

	/* END - magic ppoll dance */

	if (pollCount < 0)
	{
		if (errno == EINTR && * condition & ENET_SOCKET_WAIT_INTERRUPT)
		{
			* condition = ENET_SOCKET_WAIT_INTERRUPT;

			return 0;
		}

		return -1;
	}

	* condition = ENET_SOCKET_WAIT_NONE;

	if (pollCount == 0)
		return 0;

	if (pollSocket.revents & POLLOUT)
		* condition |= ENET_SOCKET_WAIT_SEND;

	if (pollSocket.revents & POLLIN)
		* condition |= ENET_SOCKET_WAIT_RECEIVE;

	return 0;
}

static int
enet_intr_host_bind_unix (ENetHost * host, struct ENetIntrHostData * intrHostData)
{
	if (enet_intr_host_data_already_bound (host, intrHostData))
		return 0;

	if (intrHostData -> type != ENET_INTR_DATA_TYPE_UNIX)
		return -1;

	/* would overwrite existing */
	if (host -> intrHostData)
		return -1;

	host -> intrHostData = intrHostData;

	return 0;
}

static int
enet_intr_host_destroy_unix (struct _ENetHost * host)
{
	struct ENetIntrHostDataUnix * pData = (struct ENetIntrHostDataUnix *) host -> intrHostData;

	if (! pData)
		return 0;

	if (pData -> base.type != ENET_INTR_DATA_TYPE_UNIX)
		return -1;

	enet_free (pData);

	return 0;
}

struct ENetIntrHostData *
enet_intr_host_create_and_bind_unix (struct _ENetHost * host)
{
	struct ENetIntrHostDataUnix *pData = (struct ENetIntrHostDataUnix *) enet_malloc (sizeof(struct ENetIntrHostDataUnix));

	if (! pData)
		return NULL;

	pData -> base.type = ENET_INTR_DATA_TYPE_UNIX;

	pData -> base.cb_host_create = enet_intr_host_create_and_bind_unix;
	pData -> base.cb_host_destroy = enet_intr_host_destroy_unix;
	pData -> base.cb_host_bind = enet_intr_host_bind_unix;
	pData -> base.cb_host_socket_wait_interruptible = enet_intr_host_socket_wait_interruptible_unix;

	/* bind to host */

	if (pData -> base.cb_host_bind (host, (struct ENetIntrHostData *) pData))
	{
		enet_free (pData);

		return NULL;
	}

	return & pData -> base;
}

static int
enet_intr_token_destroy_unix (struct ENetIntrToken * gentoken)
{
	struct ENetIntrTokenUnix * pToken = (struct ENetIntrTokenUnix *) gentoken;

	if (gentoken -> type != ENET_INTR_DATA_TYPE_UNIX)
		return -1;

	pToken -> idServiceThread = 0;

	if (pthread_mutex_destroy (& pToken -> mutexData))
		return -1;

	enet_free (pToken);

	return 0;
}

/** Blindly overwrite token with new host (unless already bound to it).
    If token is already bound to a host it will not be unbound
	from the old host or anything.

	Calls to this function are designed to be triggered from the ENetHost host.
	- Host has to ensure read access to intrHostData field is safe
	(sequencing, no conflicting writes, field not yet destroyed, etc).
	Ensuring this seemingly should not require locking at the host side.
	(ex since calls are only triggered from the host)
	- The current thread id will be recorded for interruption purposes.
	Obviously (?), calling host functions that trigger bind from different
	threads will result in this identifier being outdated.
	The 'last_chance' mechanism is designed to compensate.
	(bind and last_chance will be performed in order, from the same thread,
	 allowing such current thread id to be updated)
*/
static int
enet_intr_token_bind_unix (struct ENetIntrToken * intrToken, ENetHost * host)
{
	struct ENetIntrTokenUnix * pToken = (struct ENetIntrTokenUnix *) intrToken;

	if (intrToken -> type != ENET_INTR_DATA_TYPE_UNIX)
		return -1;

	if (pthread_mutex_lock (& pToken -> mutexData))
		return -1;

	/* bind on token side */
	pToken -> base.intrHostData = host -> intrHostData;

	pToken -> idServiceThread = pthread_self ();

	if (pthread_mutex_unlock (& pToken -> mutexData))
		return -1;

	return 0;
}

/** To be called from ex enet_host_destroy of a host to notify the token of destruction.
*   If the token is bound to the host, it must be disabled / unbound.
*   If the token is not bound to the host, however, no operation need be performed on the token.
*/
static int
enet_intr_token_unbind_unix (struct ENetIntrToken * gentoken, ENetHost * host)
{
	int ret = 0;

	pthread_mutex_t * pMutexData = NULL;

	struct ENetIntrTokenUnix * pToken = (struct ENetIntrTokenUnix *) gentoken;

	/* paranoia */
	if (gentoken -> type != ENET_INTR_DATA_TYPE_UNIX)
		{ ret = -1; goto clean; }

	if (pthread_mutex_lock (& pToken -> mutexData))
		{ ret = -1; goto clean; }
	/* take unlock responsibility */
	pMutexData = & pToken -> mutexData;

	if (enet_intr_token_disabled (& pToken -> base))
		{ ret = 0; goto clean; };

	/* not bound to passed host? */
	if (pToken -> base.intrHostData != host -> intrHostData)
		{ ret = 0; goto clean; };

	pToken -> base.intrHostData = NULL;

	pToken -> idServiceThread = 0;

clean:
	if (pMutexData)
		if (pthread_mutex_unlock (pMutexData))
			{ /* dummy */ }

	return ret;
}

static int
enet_intr_token_interrupt_unix (struct ENetIntrToken * gentoken)
{
	int ret = 0;

	pthread_mutex_t * pMutexData = NULL;

	struct ENetIntrTokenUnix * pToken = (struct ENetIntrTokenUnix *) gentoken;

	/* paranoia */
	if (gentoken -> type != ENET_INTR_DATA_TYPE_UNIX)
		{ ret = -1; goto clean; };

	if (pthread_mutex_lock (& pToken -> mutexData))
		{ ret = -1; goto clean; }
	/* take unlock responsibility */
	pMutexData = & pToken -> mutexData;

	if (enet_intr_token_disabled (& pToken -> base))
		{ ret = 0; goto clean; };

	/* paranoia */
	if (pToken -> base.intrHostData -> type != ENET_INTR_DATA_TYPE_UNIX)
		{ ret = -1; goto clean; };

	/* FIXME: hardcoded SIGUSR1 - make this configurable (likely at token creation) */
	if (pthread_kill (pToken -> idServiceThread, SIGUSR1))
		return -1;

clean:
	if (pMutexData)
		if (pthread_mutex_unlock (pMutexData))
			{ /* dummy */ }

	return ret;
}

struct ENetIntrToken *
enet_intr_token_create_unix (void)
{
	struct ENetIntrTokenUnix * pToken = (struct ENetIntrTokenUnix *) enet_malloc (sizeof (struct ENetIntrTokenUnix));

	pthread_mutexattr_t mutexAttr = {};

	if (!pToken)
		return NULL;

	pToken -> base.type = ENET_INTR_DATA_TYPE_UNIX;

	pToken -> base.intrHostData = NULL;

	pToken -> base.cb_token_create = enet_intr_token_create_unix;
	pToken -> base.cb_token_destroy = enet_intr_token_destroy_unix;
	pToken -> base.cb_token_bind = enet_intr_token_bind_unix;
	pToken -> base.cb_token_unbind = enet_intr_token_unbind_unix;
	pToken -> base.cb_token_interrupt = enet_intr_token_interrupt_unix;

	pToken -> idServiceThread = 0;

	if (pthread_mutexattr_init (& mutexAttr))
		return NULL;

	if (pthread_mutexattr_settype (& mutexAttr, PTHREAD_MUTEX_RECURSIVE))
		return NULL;

	if (pthread_mutex_init (& pToken -> mutexData, & mutexAttr))
		return NULL;

	if (pthread_mutexattr_destroy (& mutexAttr))
		return NULL;

	if (pthread_mutex_lock (& pToken -> mutexData))
		return NULL;

	if (pthread_mutex_unlock (& pToken -> mutexData))
		return NULL;

	return & pToken -> base;
}

int
enet_initialize (void)
{
    return 0;
}

void
enet_deinitialize (void)
{
}

enet_uint32
enet_host_random_seed (void)
{
    return (enet_uint32) time (NULL);
}

enet_uint32
enet_time_get (void)
{
    struct timeval timeVal;

    gettimeofday (& timeVal, NULL);

    return timeVal.tv_sec * 1000 + timeVal.tv_usec / 1000 - timeBase;
}

void
enet_time_set (enet_uint32 newTimeBase)
{
    struct timeval timeVal;

    gettimeofday (& timeVal, NULL);
    
    timeBase = timeVal.tv_sec * 1000 + timeVal.tv_usec / 1000 - newTimeBase;
}

int
enet_address_set_host (ENetAddress * address, const char * name)
{
#ifdef HAS_GETADDRINFO
    struct addrinfo hints, * resultList = NULL, * result = NULL;

    memset (& hints, 0, sizeof (hints));
    hints.ai_family = AF_INET;

    if (getaddrinfo (name, NULL, NULL, & resultList) != 0)
      return -1;

    for (result = resultList; result != NULL; result = result -> ai_next)
    {
        if (result -> ai_family == AF_INET && result -> ai_addr != NULL && result -> ai_addrlen >= sizeof (struct sockaddr_in))
        {
            struct sockaddr_in * sin = (struct sockaddr_in *) result -> ai_addr;

            address -> host = sin -> sin_addr.s_addr;

            freeaddrinfo (resultList);

            return 0;
        }
    }

    if (resultList != NULL)
      freeaddrinfo (resultList);
#else
    struct hostent * hostEntry = NULL;
#ifdef HAS_GETHOSTBYNAME_R
    struct hostent hostData;
    char buffer [2048];
    int errnum;

#if defined(linux) || defined(__linux) || defined(__linux__) || defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__DragonFly__)
    gethostbyname_r (name, & hostData, buffer, sizeof (buffer), & hostEntry, & errnum);
#else
    hostEntry = gethostbyname_r (name, & hostData, buffer, sizeof (buffer), & errnum);
#endif
#else
    hostEntry = gethostbyname (name);
#endif

    if (hostEntry != NULL && hostEntry -> h_addrtype == AF_INET)
    {
        address -> host = * (enet_uint32 *) hostEntry -> h_addr_list [0];

        return 0;
    }
#endif

#ifdef HAS_INET_PTON
    if (! inet_pton (AF_INET, name, & address -> host))
#else
    if (! inet_aton (name, (struct in_addr *) & address -> host))
#endif
        return -1;

    return 0;
}

int
enet_address_get_host_ip (const ENetAddress * address, char * name, size_t nameLength)
{
#ifdef HAS_INET_NTOP
    if (inet_ntop (AF_INET, & address -> host, name, nameLength) == NULL)
#else
    char * addr = inet_ntoa (* (struct in_addr *) & address -> host);
    if (addr != NULL)
    {
        size_t addrLen = strlen(addr);
        if (addrLen >= nameLength)
          return -1;
        memcpy (name, addr, addrLen + 1);
    } 
    else
#endif
        return -1;
    return 0;
}

int
enet_address_get_host (const ENetAddress * address, char * name, size_t nameLength)
{
#ifdef HAS_GETNAMEINFO
    struct sockaddr_in sin;
    int err;

    memset (& sin, 0, sizeof (struct sockaddr_in));

    sin.sin_family = AF_INET;
    sin.sin_port = ENET_HOST_TO_NET_16 (address -> port);
    sin.sin_addr.s_addr = address -> host;

    err = getnameinfo ((struct sockaddr *) & sin, sizeof (sin), name, nameLength, NULL, 0, NI_NAMEREQD);
    if (! err)
    {
        if (name != NULL && nameLength > 0 && ! memchr (name, '\0', nameLength))
          return -1;
        return 0;
    }
    if (err != EAI_NONAME)
      return -1;
#else
    struct in_addr in;
    struct hostent * hostEntry = NULL;
#ifdef HAS_GETHOSTBYADDR_R
    struct hostent hostData;
    char buffer [2048];
    int errnum;

    in.s_addr = address -> host;

#if defined(linux) || defined(__linux) || defined(__linux__) || defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__DragonFly__)
    gethostbyaddr_r ((char *) & in, sizeof (struct in_addr), AF_INET, & hostData, buffer, sizeof (buffer), & hostEntry, & errnum);
#else
    hostEntry = gethostbyaddr_r ((char *) & in, sizeof (struct in_addr), AF_INET, & hostData, buffer, sizeof (buffer), & errnum);
#endif
#else
    in.s_addr = address -> host;

    hostEntry = gethostbyaddr ((char *) & in, sizeof (struct in_addr), AF_INET);
#endif

    if (hostEntry != NULL)
    {
       size_t hostLen = strlen (hostEntry -> h_name);
       if (hostLen >= nameLength)
         return -1;
       memcpy (name, hostEntry -> h_name, hostLen + 1);
       return 0;
    }
#endif

    return enet_address_get_host_ip (address, name, nameLength);
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
                 sizeof (struct sockaddr_in)); 
}

int
enet_socket_get_address (ENetSocket socket, ENetAddress * address)
{
    struct sockaddr_in sin;
    socklen_t sinLength = sizeof (struct sockaddr_in);

    if (getsockname (socket, (struct sockaddr *) & sin, & sinLength) == -1)
      return -1;

    address -> host = (enet_uint32) sin.sin_addr.s_addr;
    address -> port = ENET_NET_TO_HOST_16 (sin.sin_port);

    return 0;
}

int 
enet_socket_listen (ENetSocket socket, int backlog)
{
    return listen (socket, backlog < 0 ? SOMAXCONN : backlog);
}

ENetSocket
enet_socket_create (ENetSocketType type)
{
    return socket (PF_INET, type == ENET_SOCKET_TYPE_DATAGRAM ? SOCK_DGRAM : SOCK_STREAM, 0);
}

int
enet_socket_set_option (ENetSocket socket, ENetSocketOption option, int value)
{
    int result = -1;
    switch (option)
    {
        case ENET_SOCKOPT_NONBLOCK:
#ifdef HAS_FCNTL
            result = fcntl (socket, F_SETFL, (value ? O_NONBLOCK : 0) | (fcntl (socket, F_GETFL) & ~O_NONBLOCK));
#else
            result = ioctl (socket, FIONBIO, & value);
#endif
            break;

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
        {
            struct timeval timeVal;
            timeVal.tv_sec = value / 1000;
            timeVal.tv_usec = (value % 1000) * 1000;
            result = setsockopt (socket, SOL_SOCKET, SO_RCVTIMEO, (char *) & timeVal, sizeof (struct timeval));
            break;
        }

        case ENET_SOCKOPT_SNDTIMEO:
        {
            struct timeval timeVal;
            timeVal.tv_sec = value / 1000;
            timeVal.tv_usec = (value % 1000) * 1000;
            result = setsockopt (socket, SOL_SOCKET, SO_SNDTIMEO, (char *) & timeVal, sizeof (struct timeval));
            break;
        }

        case ENET_SOCKOPT_NODELAY:
            result = setsockopt (socket, IPPROTO_TCP, TCP_NODELAY, (char *) & value, sizeof (int));
            break;

        default:
            break;
    }
    return result == -1 ? -1 : 0;
}

int
enet_socket_get_option (ENetSocket socket, ENetSocketOption option, int * value)
{
    int result = -1;
    socklen_t len;
    switch (option)
    {
        case ENET_SOCKOPT_ERROR:
            len = sizeof (int);
            result = getsockopt (socket, SOL_SOCKET, SO_ERROR, value, & len);
            break;

        default:
            break;
    }
    return result == -1 ? -1 : 0;
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
    if (result == -1 && errno == EINPROGRESS)
      return 0;

    return result;
}

ENetSocket
enet_socket_accept (ENetSocket socket, ENetAddress * address)
{
    int result;
    struct sockaddr_in sin;
    socklen_t sinLength = sizeof (struct sockaddr_in);

    result = accept (socket, 
                     address != NULL ? (struct sockaddr *) & sin : NULL, 
                     address != NULL ? & sinLength : NULL);
    
    if (result == -1)
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
    return shutdown (socket, (int) how);
}

void
enet_socket_destroy (ENetSocket socket)
{
    if (socket != -1)
      close (socket);
}

int
enet_socket_send (ENetSocket socket,
                  const ENetAddress * address,
                  const ENetBuffer * buffers,
                  size_t bufferCount)
{
    struct msghdr msgHdr;
    struct sockaddr_in sin;
    int sentLength;

    memset (& msgHdr, 0, sizeof (struct msghdr));

    if (address != NULL)
    {
        memset (& sin, 0, sizeof (struct sockaddr_in));

        sin.sin_family = AF_INET;
        sin.sin_port = ENET_HOST_TO_NET_16 (address -> port);
        sin.sin_addr.s_addr = address -> host;

        msgHdr.msg_name = & sin;
        msgHdr.msg_namelen = sizeof (struct sockaddr_in);
    }

    msgHdr.msg_iov = (struct iovec *) buffers;
    msgHdr.msg_iovlen = bufferCount;

    sentLength = sendmsg (socket, & msgHdr, MSG_NOSIGNAL);
    
    if (sentLength == -1)
    {
       if (errno == EWOULDBLOCK)
         return 0;

       return -1;
    }

    return sentLength;
}

int
enet_socket_receive (ENetSocket socket,
                     ENetAddress * address,
                     ENetBuffer * buffers,
                     size_t bufferCount)
{
    struct msghdr msgHdr;
    struct sockaddr_in sin;
    int recvLength;

    memset (& msgHdr, 0, sizeof (struct msghdr));

    if (address != NULL)
    {
        msgHdr.msg_name = & sin;
        msgHdr.msg_namelen = sizeof (struct sockaddr_in);
    }

    msgHdr.msg_iov = (struct iovec *) buffers;
    msgHdr.msg_iovlen = bufferCount;

    recvLength = recvmsg (socket, & msgHdr, MSG_NOSIGNAL);

    if (recvLength == -1)
    {
       if (errno == EWOULDBLOCK)
         return 0;

       return -1;
    }

#ifdef HAS_MSGHDR_FLAGS
    if (msgHdr.msg_flags & MSG_TRUNC)
      return -1;
#endif

    if (address != NULL)
    {
        address -> host = (enet_uint32) sin.sin_addr.s_addr;
        address -> port = ENET_NET_TO_HOST_16 (sin.sin_port);
    }

    return recvLength;
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
#ifdef HAS_POLL
    struct pollfd pollSocket;
    int pollCount;
    
    pollSocket.fd = socket;
    pollSocket.events = 0;

    if (* condition & ENET_SOCKET_WAIT_SEND)
      pollSocket.events |= POLLOUT;

    if (* condition & ENET_SOCKET_WAIT_RECEIVE)
      pollSocket.events |= POLLIN;

    pollCount = poll (& pollSocket, 1, timeout);

    if (pollCount < 0)
    {
        if (errno == EINTR && * condition & ENET_SOCKET_WAIT_INTERRUPT)
        {
            * condition = ENET_SOCKET_WAIT_INTERRUPT;

            return 0;
        }

        return -1;
    }

    * condition = ENET_SOCKET_WAIT_NONE;

    if (pollCount == 0)
      return 0;

    if (pollSocket.revents & POLLOUT)
      * condition |= ENET_SOCKET_WAIT_SEND;
    
    if (pollSocket.revents & POLLIN)
      * condition |= ENET_SOCKET_WAIT_RECEIVE;

    return 0;
#else
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
    {
        if (errno == EINTR && * condition & ENET_SOCKET_WAIT_INTERRUPT)
        {
            * condition = ENET_SOCKET_WAIT_INTERRUPT;

            return 0;
        }
      
        return -1;
    }

    * condition = ENET_SOCKET_WAIT_NONE;

    if (selectCount == 0)
      return 0;

    if (FD_ISSET (socket, & writeSet))
      * condition |= ENET_SOCKET_WAIT_SEND;

    if (FD_ISSET (socket, & readSet))
      * condition |= ENET_SOCKET_WAIT_RECEIVE;

    return 0;
#endif
}

#endif

