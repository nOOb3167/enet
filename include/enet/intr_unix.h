/**
@file  intr_unix.h
@brief ENet Unix header (interruption support)
*/
#ifndef __ENET_INTR_UNIX_H__
#define __ENET_INTR_UNIX_H__

#include "enet/unix.h"

struct _ENetHost;
struct ENetIntrHostData;
struct ENetIntrToken;

ENET_API struct ENetIntrHostData * enet_intr_host_create_and_bind_unix (struct _ENetHost *);
ENET_API struct ENetIntrToken *    enet_intr_token_create_unix (void);

#endif /* __ENET_INTR_UNIX_H__ */
