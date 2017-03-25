/**
@file  intr_defs.h
@brief ENet all platform header (interruption support)

special header - include either enet/unix.h or enet/win32.h (platform specific header) before this.
*/
#ifndef __ENET_INTR_DEFS_H__
#define __ENET_INTR_DEFS_H__

struct _ENetHost;
struct ENetIntrHostData;
struct ENetIntrToken;

/* platform funcs - implement for all platforms (but stubs for everything except 'this' platform) */

ENET_API struct ENetIntrHostData *         enet_intr_host_create_and_bind_win32 (struct _ENetHost *);
ENET_API struct ENetIntrTokenCreateFlags * enet_intr_token_create_flags_create_win32 (void);
ENET_API struct ENetIntrToken *            enet_intr_token_create_win32 (void);

ENET_API struct ENetIntrHostData *         enet_intr_host_create_and_bind_unix (struct _ENetHost *);
ENET_API struct ENetIntrTokenCreateFlags * enet_intr_token_create_flags_create_unix (void);
ENET_API struct ENetIntrToken *            enet_intr_token_create_unix (void);


#endif /* __ENET_INTR_DEFS_H__ */
