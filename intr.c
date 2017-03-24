/**
@file  intr.c
@brief ENet functions (interruption support)
*/

#define ENET_BUILDING_LIB 1
#include "enet/enet.h"

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
