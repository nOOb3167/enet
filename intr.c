/**
@file  intr.c
@brief ENet functions (interruption support)
*/

#define ENET_BUILDING_LIB 1
#include "enet/enet.h"

int
enet_intr_host_data_already_bound_any (struct _ENetHost * host)
{
	return host -> intrHostData;
}

/**
    @retval > 0 if host already bound to (the same) intrHostData
	@retval 0 otherwise
*/
int
enet_intr_host_data_already_bound (struct _ENetHost * host, struct ENetIntrHostData * intrHostData)
{
	return (host -> intrHostData == intrHostData);
}

int
enet_intr_token_already_bound (struct _ENetHost * host, struct ENetIntrToken * intrToken)
{
	return (host -> intrToken == intrToken);
}

int
enet_intr_token_disabled (struct ENetIntrToken * intrToken)
{
	return ! intrToken -> intrHostData;
}

struct _ENetHost *
enet_host_create_interruptible (const struct _ENetAddress * address, size_t peerCount, size_t channelLimit, enet_uint32 incomingBandwidth, enet_uint32 outgoingBandwidth, const struct ENetIntrHostCreateFlags * flags)
{
	ENetHost *                host         = NULL;
	struct ENetIntrHostData * intrHostData = NULL;
	enum ENetIntrDataType     platformType = 0;
	enum ENetIntrDataType     createType   = flags -> type;

	/* FIXME: any better way of determining platform type? */
#ifdef _WIN32
	platformType = ENET_INTR_DATA_TYPE_WIN32;
#else
	platformType = ENET_INTR_DATA_TYPE_UNIX;
#endif

	if (!(host = enet_host_create (address, peerCount, channelLimit, incomingBandwidth, outgoingBandwidth)))
		return NULL;

	if (flags->version != ENET_INTR_HOST_CREATE_FLAGS_VERSION_DONTCARE)
	{
		enet_host_destroy(host);

		return NULL;
	}

	/* FIXME: any better way of defaulting the type? */
	if (! flags -> notAllDefault)
	{
		createType = platformType;
	}

	switch (createType)
	{
	case ENET_INTR_DATA_TYPE_WIN32:
		intrHostData = enet_intr_host_create_and_bind_win32 (host);
		break;

	case ENET_INTR_DATA_TYPE_UNIX:
		intrHostData = enet_intr_host_create_and_bind_unix (host);
		break;

	default:
		break;
	}

	if (intrHostData == NULL)
	{
		enet_host_destroy (host);

		return NULL;
	}

	return host;
}
