/**
@file  intr.c
@brief ENet functions (interruption support)
*/

#define ENET_BUILDING_LIB 1
#include "enet/enet.h"


static enum ENetIntrDataType
enet_intr_platform_type (void)
{
	/* FIXME: any better way of determining platform type? */
#ifdef _WIN32
	return ENET_INTR_DATA_TYPE_WIN32;
#else
	return ENET_INTR_DATA_TYPE_UNIX;
#endif
}

int
enet_intr_host_data_already_bound_any (struct _ENetHost * host)
{
	return !! host -> intrHostData;
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

ENetHost *
enet_host_create_interruptible (const ENetAddress * address, size_t peerCount, size_t channelLimit, enet_uint32 incomingBandwidth, enet_uint32 outgoingBandwidth, const struct ENetIntrHostCreateFlags * flags)
{
	ENetHost *                host         = NULL;
	struct ENetIntrHostData * intrHostData = NULL;
	enum ENetIntrDataType     platformType = enet_intr_platform_type ();
	enum ENetIntrDataType     createType   = flags -> notAllDefault ? flags -> type : platformType;;

	if (flags -> version != ENET_INTR_HOST_CREATE_FLAGS_VERSION_DONTCARE)
		return NULL;

	if (!(host = enet_host_create (address, peerCount, channelLimit, incomingBandwidth, outgoingBandwidth)))
		return NULL;

	switch (createType)
	{
	case ENET_INTR_DATA_TYPE_WIN32:
		intrHostData = enet_intr_host_create_and_bind_win32 (host);
		break;

	case ENET_INTR_DATA_TYPE_UNIX:
		intrHostData = enet_intr_host_create_and_bind_unix (host);
		break;
	}

	if (intrHostData == NULL)
	{
		enet_host_destroy (host);

		return NULL;
	}

	return host;
}

/**
    @param type ENET_INTR_DATA_TYPE_NONE for default
*/
struct ENetIntrTokenCreateFlags *
enet_intr_token_create_flags_create (enum ENetIntrDataType type)
{
	struct ENetIntrTokenCreateFlags * flags = NULL;
	enum ENetIntrDataType  platformType = enet_intr_platform_type ();
	enum ENetIntrDataType  createType = (type != ENET_INTR_DATA_TYPE_NONE) ? type : platformType;

	switch (createType)
	{
	case ENET_INTR_DATA_TYPE_WIN32:
		flags = enet_intr_token_create_flags_create_win32 ();
		break;

	case ENET_INTR_DATA_TYPE_UNIX:
		flags = enet_intr_token_create_flags_create_unix ();
		break;
	}

	if (flags == NULL)
		return NULL;

	return flags;
}

struct ENetIntrToken *
enet_intr_token_create (const struct ENetIntrTokenCreateFlags *flags)
{
	struct ENetIntrToken * intrToken = NULL;
	enum ENetIntrDataType  platformType = enet_intr_platform_type ();
	enum ENetIntrDataType  createType = flags -> notAllDefault ? flags -> type : platformType;

	if (flags->version != ENET_INTR_TOKEN_CREATE_FLAGS_VERSION_DONTCARE)
		return NULL;

	switch (createType)
	{
	case ENET_INTR_DATA_TYPE_WIN32:
		intrToken = enet_intr_token_create_win32 ();
		break;

	case ENET_INTR_DATA_TYPE_UNIX:
		intrToken = enet_intr_token_create_unix ();
		break;
	}

	if (intrToken == NULL)
		return NULL;

	return intrToken;
}
