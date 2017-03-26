/**
@file  intr_win32.c
@brief ENet Win32 system specific functions (interruption support)

This interruption support method relies on WSAEventSelect.
The general WSAEventSelect code flow is described below.

@code{.c}
WSAEVENT SocketEvent = WSACreateEvent ();
WSAEventSelect (socket, SocketEvent, FD_READ);
@endcode

WSAEventSelect associates an event with a socket.
The socket event association will cause the event to be signalled on network activity.

@code{.c}
HANDLE InterruptEvent = CreateEvent ();
@endcode

Another (programmatically signallizable) event can be created.
This second event can be signalled (using SetEvent) when interruption desired.

@code{.c}
EventArray[0] = InterruptEvent;
EventArray[1] = SocketEvent;
WSAWaitForMultipleEvents (..., EventArray, ...);
if (wait_completed_due_to_socket_event)
    WSAEnumNetworkEvents (..., SocketEvent, events);
@endcode

WSAWaitForMultipleEvents is used to wait for an event to become signalled.
It is possible to determine which of the events caused the call to complete.

To implement interruption, having the call complete is all that is needed.

To allow reacting to network events, WSAEnumNetworkEvents allows checking
for events arrived since the last WSAEnumNetworkEvents call.

*/

#define ENET_BUILDING_LIB 1
#include "enet/enet.h"
#include "enet/intr.h"
#include "enet/intr_win32.h"
#include <windows.h>

/** @sa ::enet_intr_host_create_and_bind_win32 */
struct ENetIntrHostDataWin32
{
	struct ENetIntrHostData base;

	WSAEVENT EventSocket;      /**< empty value: WSA_INVALID_EVENT */
	HANDLE   hEventInterrupt;  /**< empty value: NULL */
};

/** @sa ::enet_intr_token_create_flags_create_win32 */
struct ENetIntrTokenCreateFlagsWin32
{
	struct ENetIntrTokenCreateFlags base;
};

/** @sa ::enet_intr_token_create_win32 */
struct ENetIntrTokenWin32
{
	struct ENetIntrToken base;

	CRITICAL_SECTION mutexData;
};

/** Perform similar role as poll(2).

	The Win32 API function WSAWaitForMultipleEvents is presumably
	able to wait both on WSA Events (ex created with WSACreateEvent)
	and 'normal' events (ex created with CreateEvent).

	<a href="https://blogs.msdn.microsoft.com/geoffda/2008/08/18/beware-of-auto-reset-events-they-dont-behave-the-way-you-think-they-do/">However (click link)</a>
	there appear to be some reports of <b>auto-reset</b> 'normal' events interacting poorly with waits.

	@code{.c}
	HANDLE hEvent[2] = {};
	hEvent[0] = CreateEvent(NULL, FALSE, FALSE, NULL);
	hEvent[1] = CreateEvent(NULL, FALSE, FALSE, NULL);
	SetEvent(hEvent[0]);
	SetEvent(hEvent[1]);
	while (true) {
	    DWORD ret = WaitForMultipleObjects(2, hEvent, FALSE, 1000);
		printf("ret [%d]\n", (int)ret);
	}
	printf("end\n");
	@endcode

	@verbatim
	ret [0]    // WaitForMultipleObjects succeeds with first event
	ret [1]    // WaitForMultipleObjects succeeds with second event
	ret [258]  // timeout return code
	...
	@endverbatim

	Interpret the result of the code above as follows:
	An <b>auto-reset</b> event that has been set (ex SetEvent), is not reset by WaitForMultipleObjects,
	unless it is the one that actually caused the wait call to complete.
	Thus after <b>ret [0]</b> we have <b>ret [1]</b>, as only the first event has reset in the first loop iteration.

	@retval > 0 if an event occurred within the specified time limit.
	            specifically: 1 on interrupt and 2 on socket event.
	@retval 0 if no event occurred
	@retval < 0 on failure
*/
static int
enet_intr_host_data_helper_event_wait (ENetHost * host, enet_uint32 timeoutMsec)
{
	struct ENetIntrHostDataWin32 * pHostData = (struct ENetIntrHostDataWin32 *) host -> intrHostData;

	/* FIXME: can use both WSACreateEvent and CreateEvent events
	*    in WSAWaitForMultipleEvents but is the type WSAEVENT or HANDLE? */
	WSAEVENT EventArray[2] = { 0 };

	DWORD ret = 0;
	DWORD indexSignaled = 0;

	if (host -> intrHostData -> type != ENET_INTR_DATA_TYPE_WIN32)
		return -1;

	EventArray[0] = pHostData -> hEventInterrupt;
	EventArray[1] = pHostData -> EventSocket;

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

/** The WSAEnumNetworkEvents part of the WSAEventSelect pattern.

	With respect to the (non-)handling of write events, see ::enet_intr_host_data_helper_make_event .

	@param[in,out] condition input mask of events to check for.
				   (but only ENET_SOCKET_WAIT_RECEIVE and ENET_SOCKET_WAIT_SEND)
				   output mask of events that have occurred / are ready for processing.
*/
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

	With respect to the FD_READ mask, see
	<a href="https://msdn.microsoft.com/en-us/library/windows/desktop/ms741576(v=vs.85).aspx">the following MSDN page(click link)</a>:
	"""The FD_WRITE network event is handled slightly differently. ...""".
	It does not seem including FD_WRITE has useful semantics.

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

static int
enet_intr_host_data_helper_free_event (WSAEVENT * outputWSAEventSocket, HANDLE * outputHWSAEventInterrupt)
{
	if (! WSACloseEvent (* outputWSAEventSocket))
		return -1;

	if (! CloseHandle (* outputHWSAEventInterrupt))
		return -1;

	return 0;
}

/** Delegate binding to the passed-in token, and finish up by setting host -> intrToken.
*/
static int
enet_intr_host_token_bind(ENetHost * host, struct ENetIntrToken * intrToken)
{
	/* early exit */
	if (enet_intr_token_already_bound (host, intrToken))
		return 0;

	if (intrToken -> type != ENET_INTR_DATA_TYPE_WIN32)
		return -1;

	if (intrToken -> cb_token_bind (intrToken, host))
		return -1;

	host -> intrToken = intrToken;

	return 0;
}

/**

	The following condition states may be output:
	- ENET_SOCKET_WAIT_NONE: no events have in fact occurred.
	- ENET_SOCKET_WAIT_INTERRUPT: an interruption occurred.
	- combination of ENET_SOCKET_WAIT_RECEIVE and ENET_SOCKET_WAIT_SEND: a network event occurred.

    @param[in,out] condition input mask of events to check for.
							 output mask of events that have occurred.
*/
static int
enet_intr_host_socket_wait_interruptible_win32 (ENetHost * host, enet_uint32 * condition, enet_uint32 timeout, struct ENetIntrToken * intrToken, struct ENetIntr * intr)
{
	int retSocketWait = 0;

	if (! enet_intr_host_data_already_bound_any (host))
		return -1;

	if (enet_intr_host_token_bind (host, intrToken))
		return -1;

	intr -> cb_last_chance (intrToken);

	retSocketWait = enet_intr_host_data_helper_event_wait (host, timeout);

	if (retSocketWait < 0)
		return -1;

	if (retSocketWait == 0)
	{
		* condition = ENET_SOCKET_WAIT_NONE;
	}
	else if (retSocketWait == 1)
	{
		* condition = ENET_SOCKET_WAIT_INTERRUPT;
	}
	else if (retSocketWait == 2)
	{
		if (enet_intr_host_data_helper_event_enum (host, condition))
			return -1;
	}

	return 0;
}

static int
enet_intr_host_bind_win32 (ENetHost * host, struct ENetIntrHostData * intrHostData)
{
	/* FIXME: this might be an error instead of a no-op surely? */
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

static int
enet_intr_token_destroy_win32 (struct ENetIntrToken * gentoken)
{
	struct ENetIntrTokenWin32 * pToken = (struct ENetIntrTokenWin32 *) gentoken;

	if (pToken -> base.type != ENET_INTR_DATA_TYPE_WIN32)
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
	Ensuring this seemingly should not require locking at the host side.
	(ex since calls are only triggered from the host)
*/
static int
enet_intr_token_bind_win32 (struct ENetIntrToken * intrToken, ENetHost * host)
{
	struct ENetIntrTokenWin32 * pToken = (struct ENetIntrTokenWin32 *) intrToken;

	if (pToken -> base.type != ENET_INTR_DATA_TYPE_WIN32)
		return -1;

	EnterCriticalSection (& pToken -> mutexData);

	/* bind on token side */
	pToken -> base.intrHostData = host -> intrHostData;

	LeaveCriticalSection (& pToken -> mutexData);

	return 0;
}

/** To be called from ex enet_host_destroy of a host to notify the token of destruction.
*   If the token is bound to the host, it must be disabled / unbound.
*   If the token is not bound to the host, however, no operation need be performed on the token.
*/
static int
enet_intr_token_unbind_win32 (struct ENetIntrToken * gentoken, ENetHost * host)
{
	struct ENetIntrTokenWin32 * pToken = (struct ENetIntrTokenWin32 *) gentoken;

	if (pToken -> base.type != ENET_INTR_DATA_TYPE_WIN32)
		return -1;

	EnterCriticalSection (& pToken -> mutexData);

	if (enet_intr_token_disabled (& pToken -> base))
	{
		LeaveCriticalSection(& pToken -> mutexData);

		return 0;
	}

	/* not bound to passed host? */
	if (pToken -> base.intrHostData != host -> intrHostData)
	{
		LeaveCriticalSection(& pToken -> mutexData);

		return 0;
	}

	pToken -> base.intrHostData = NULL;

	return 0;
}

static int
enet_intr_token_interrupt_win32 (struct ENetIntrToken * gentoken)
{
	int ret = 0;

	LPCRITICAL_SECTION pMutexData = NULL;

	struct ENetIntrTokenWin32 *    pToken = (struct ENetIntrTokenWin32 *) gentoken;
	struct ENetIntrHostDataWin32 * pData =  (struct ENetIntrHostDataWin32 *) gentoken -> intrHostData;

	if (pToken -> base.type != ENET_INTR_DATA_TYPE_WIN32)
		return -1;

	EnterCriticalSection (& pToken -> mutexData);

	if (enet_intr_token_disabled (& pToken -> base))
	{
		LeaveCriticalSection(& pToken -> mutexData);

		return 0;
	}

	/* NOTE: withing lock and after disablement check
	*        ensure eg synchronization against host destruction */
	if (pData -> base.type != ENET_INTR_DATA_TYPE_WIN32)
	{
		LeaveCriticalSection(& pToken -> mutexData);

		return -1;
	}

	if (! SetEvent (pData -> hEventInterrupt))
	{
		LeaveCriticalSection(& pToken -> mutexData);

		return -1;
	}

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

struct ENetIntrTokenCreateFlags *
enet_intr_token_create_flags_create_win32 (void)
{
	struct ENetIntrTokenCreateFlagsWin32 * pFlags = (struct ENetIntrTokenCreateFlagsWin32 *) enet_malloc (sizeof (struct ENetIntrTokenCreateFlagsWin32));

	pFlags -> base.type = ENET_INTR_DATA_TYPE_WIN32;

	pFlags -> base.version = ENET_INTR_TOKEN_CREATE_FLAGS_VERSION_DONTCARE;
	pFlags -> base.notAllDefault = 0;

	return & pFlags -> base;
}

struct ENetIntrToken *
enet_intr_token_create_win32 (const struct ENetIntrTokenCreateFlags * flags)
{
	struct ENetIntrTokenWin32 * pToken = (struct ENetIntrTokenWin32 *) enet_malloc (sizeof (struct ENetIntrTokenWin32));

	if (!pToken)
		return NULL;

	pToken -> base.type = ENET_INTR_DATA_TYPE_WIN32;

	pToken -> base.intrHostData = NULL;

	pToken -> base.cb_token_create = enet_intr_token_create_win32;
	pToken -> base.cb_token_destroy = enet_intr_token_destroy_win32;
	pToken -> base.cb_token_bind = enet_intr_token_bind_win32;
	pToken -> base.cb_token_unbind = enet_intr_token_unbind_win32;
	pToken -> base.cb_token_interrupt = enet_intr_token_interrupt_win32;

	InitializeCriticalSection (& pToken -> mutexData);

	EnterCriticalSection (& pToken -> mutexData);
	LeaveCriticalSection (& pToken -> mutexData);

	return & pToken -> base;
}

struct ENetIntrHostData *
enet_intr_host_create_and_bind_unix (struct _ENetHost * host)
{
	return NULL;
}

struct ENetIntrTokenCreateFlags *
enet_intr_token_create_flags_create_unix (void)
{
	return NULL;
}

struct ENetIntrToken *
enet_intr_token_create_unix (const struct ENetIntrTokenCreateFlags * flags)
{
	return NULL;
}
