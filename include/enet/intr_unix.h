/**
@file  intr_unix.h
@brief ENet Unix header (interruption support)
*/
#ifndef __ENET_INTR_UNIX_H__
#define __ENET_INTR_UNIX_H__

#include "enet/unix.h"
#include "enet/intr_defs.h"

ENET_API int enet_intr_token_create_flags_set_signo (struct ENetIntrTokenCreateFlags * flags, int signo);

#endif /* __ENET_INTR_UNIX_H__ */
