/**
@file  intr.h
@brief ENet header (interruption support)
*/
#ifndef __ENET_INTR_H__
#define __ENET_INTR_H__

struct _ENetHost;
struct ENetIntrHostData;
struct ENetIntrToken;

int enet_intr_host_data_already_bound (struct _ENetHost * host, struct ENetIntrHostData * intrHostData);
int enet_intr_token_already_bound     (struct _ENetHost * host, struct ENetIntrToken * intrToken);
int enet_intr_token_disabled          (struct ENetIntrToken * intrToken);

#endif /* __ENET_INTR_H__ */
