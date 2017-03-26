/**
@file  intr_unix.c
@brief ENet Unix system specific functions (interruption support)
*/

#define _GNU_SOURCE  // for ppoll

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>

#define ENET_BUILDING_LIB 1
#include "enet/enet.h"
#include "enet/intr.h"
#include "enet/intr_unix.h"

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

#if defined HAS_POLL || defined HAS_PPOLL
#include <poll.h>
#endif

#define ENET_UNIX_DEFAULT_SIGNO SIGUSR1

/** @sa ::enet_intr_host_create_and_bind_unix */
struct ENetIntrHostDataUnix
{
	struct ENetIntrHostData base;
};

/** @sa ::enet_intr_token_create_flags_create_unix */
struct ENetIntrTokenCreateFlagsUnix
{
	struct ENetIntrTokenCreateFlags base;

	int signo;
};

/** @sa ::enet_intr_token_create_unix */
struct ENetIntrTokenUnix
{
	struct ENetIntrToken base;

	pthread_t idServiceThread;

	int signo;

	pthread_mutex_t mutexData;
};

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

/** Regarding timespec use with ppoll, NULL pointer
    timespec argument means indefinite wait.
	Not available through this API.
*/
static void
enet_unix_helper_convert_timeout_timespec (enet_uint32 timeoutMs, struct timespec *outputTimespec)
{
	outputTimespec->tv_sec = timeoutMs / 1000;
	outputTimespec->tv_nsec = (timeoutMs % 1000) * 1000000;
}

static int
enet_intr_host_socket_wait_interruptible_unix (ENetHost * host, enet_uint32 * condition, enet_uint32 timeout, struct ENetIntrToken * intrToken, struct ENetIntr * intr)
{
	if (! enet_intr_host_data_already_bound_any (host))
		return -1;

	if (enet_intr_host_token_bind (host, intrToken))
		return -1;

#if ! (defined HAS_PPOLL || defined HAS_PSELECT)
#  error have neither ppoll nor pselect despite compiling interruption support
#elif defined HAS_PPOLL

	struct pollfd pollSocket;
	int pollCount;

	sigset_t oldSigSet = {};
	sigset_t newSigSet = {};

	struct timespec timespecTimeout = {};
	
	enet_unix_helper_convert_timeout_timespec (timeout, & timespecTimeout);

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

	pollCount = ppoll (& pollSocket, 1, & timespecTimeout, & oldSigSet);

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

#elif defined HAS_PSELECT

	fd_set readSet, writeSet;
    int selectCount;

	sigset_t oldSigSet = {};
	sigset_t newSigSet = {};

	struct timespec timespecTimeout = {};

	enet_unix_helper_convert_timeout_timespec (timeout, & timespecTimeout);

    FD_ZERO (& readSet);
    FD_ZERO (& writeSet);

    if (* condition & ENET_SOCKET_WAIT_SEND)
      FD_SET (socket, & writeSet);

    if (* condition & ENET_SOCKET_WAIT_RECEIVE)
      FD_SET (socket, & readSet);

	/* BEGIN - magic pselect dance */

	if (sigfillset (&newSigSet))
		return -1;

	if (pthread_sigmask (SIG_SETMASK, & newSigSet, & oldSigSet))
		return -1;

	intr->cb_last_chance (intrToken);

    selectCount = pselect (socket + 1, & readSet, & writeSet, NULL, & timespecTimeout, & oldSigSet);

	if (pthread_sigmask (SIG_SETMASK, & oldSigSet, NULL))
		return -1;

	/* END - magic pselect dance */

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

static int
enet_intr_token_destroy_unix (struct ENetIntrToken * gentoken)
{
	struct ENetIntrTokenUnix * pToken = (struct ENetIntrTokenUnix *) gentoken;

	if (pToken -> base.type != ENET_INTR_DATA_TYPE_UNIX)
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

	if (pToken -> base.type != ENET_INTR_DATA_TYPE_UNIX)
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
	struct ENetIntrTokenUnix * pToken = (struct ENetIntrTokenUnix *) gentoken;

	if (pToken -> base.type != ENET_INTR_DATA_TYPE_UNIX)
		return -1;

	if (pthread_mutex_lock (& pToken -> mutexData))
		return -1;

	if (enet_intr_token_disabled (& pToken -> base))
	{
		if (pthread_mutex_unlock (& pToken -> mutexData))
			return -1;

		return 0;
	}

	/* not bound to passed host? */
	if (pToken -> base.intrHostData != host -> intrHostData)
	{
		if (pthread_mutex_unlock (& pToken -> mutexData))
			return -1;

		return 0;
	}

	pToken -> base.intrHostData = NULL;

	pToken -> idServiceThread = 0;

	return 0;
}

static int
enet_intr_token_interrupt_unix (struct ENetIntrToken * gentoken)
{
	struct ENetIntrTokenUnix * pToken = (struct ENetIntrTokenUnix *) gentoken;

	if (pToken -> base.type != ENET_INTR_DATA_TYPE_UNIX)
		return -1;

	if (pthread_mutex_lock (& pToken -> mutexData))
		return -1;

	if (enet_intr_token_disabled (& pToken -> base))
	{
		if (pthread_mutex_unlock (& pToken -> mutexData))
			return -1;

		return 0;
	}

	if (pToken -> base.intrHostData -> type != ENET_INTR_DATA_TYPE_UNIX)
	{
		if (pthread_mutex_unlock (& pToken -> mutexData))
			return -1;

		return -1;
	}

	/* FIXME: hardcoded SIGUSR1 - make this configurable (likely at token creation) */
	if (pthread_kill (pToken -> idServiceThread, pToken -> signo))
	{
		if (pthread_mutex_unlock (& pToken -> mutexData))
			return -1;

		return -1;
	}

	return 0;
}

int
enet_intr_token_create_flags_set_signo (struct ENetIntrTokenCreateFlags * flags, int signo)
{
	struct ENetIntrTokenCreateFlagsUnix * pFlags = (struct ENetIntrTokenCreateFlagsUnix *) flags;

	if (pFlags -> base.type != ENET_INTR_DATA_TYPE_UNIX)
		return -1;
	
	pFlags -> base.notAllDefault = 1;

	pFlags -> signo = signo;

	return 0;
}

struct ENetIntrHostData *
enet_intr_host_create_and_bind_win32 (struct _ENetHost * host)
{
	return NULL;
}

struct ENetIntrTokenCreateFlags *
enet_intr_token_create_flags_create_win32 (void)
{
	return NULL;
}

struct ENetIntrToken *
enet_intr_token_create_win32 (const struct ENetIntrTokenCreateFlags * flags)
{
	return NULL;
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

struct ENetIntrTokenCreateFlags *
enet_intr_token_create_flags_create_unix (void)
{
	struct ENetIntrTokenCreateFlagsUnix * pFlags = (struct ENetIntrTokenCreateFlagsUnix *) enet_malloc (sizeof (struct ENetIntrTokenCreateFlagsUnix));

	pFlags -> base.type = ENET_INTR_DATA_TYPE_UNIX;

	pFlags -> base.version = ENET_INTR_TOKEN_CREATE_FLAGS_VERSION_DONTCARE;
	pFlags -> base.notAllDefault = 0;

	pFlags -> signo = ENET_UNIX_DEFAULT_SIGNO;

	return & pFlags -> base;
}

struct ENetIntrToken *
enet_intr_token_create_unix (const struct ENetIntrTokenCreateFlags * flags)
{
	struct ENetIntrTokenUnix * pToken = (struct ENetIntrTokenUnix *) enet_malloc (sizeof (struct ENetIntrTokenUnix));
	struct ENetIntrTokenCreateFlagsUnix * pFlags = (struct ENetIntrTokenCreateFlagsUnix *) flags;

	pthread_mutexattr_t mutexAttr = {};

	if (!pToken)
		return NULL;

	if (pFlags -> base.type != ENET_INTR_DATA_TYPE_UNIX)
		return NULL;

	pToken -> base.type = ENET_INTR_DATA_TYPE_UNIX;

	pToken -> base.intrHostData = NULL;

	pToken -> base.cb_token_create = enet_intr_token_create_unix;
	pToken -> base.cb_token_destroy = enet_intr_token_destroy_unix;
	pToken -> base.cb_token_bind = enet_intr_token_bind_unix;
	pToken -> base.cb_token_unbind = enet_intr_token_unbind_unix;
	pToken -> base.cb_token_interrupt = enet_intr_token_interrupt_unix;

	pToken -> idServiceThread = 0;

	/* FIXME: handle pFlags -> notAllDefault ? */
	pToken -> signo = pFlags -> signo;

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
