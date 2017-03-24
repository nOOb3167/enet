/**
@file  intr_win32.h
@brief ENet Win32 header (interruption support)
*/
#ifndef __ENET_INTR_WIN32_H__
#define __ENET_INTR_WIN32_H__

#include "enet/win32.h"

struct _ENetHost;
struct ENetIntrHostData;
struct ENetIntrToken;

ENET_API struct ENetIntrHostData * enet_intr_host_create_and_bind_win32(struct _ENetHost *);
ENET_API struct ENetIntrToken *    enet_intr_token_create_win32(void);

#endif /* __ENET_INTR_WIN32_H__ */
