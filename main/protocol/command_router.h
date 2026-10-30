#ifndef COMMAND_ROUTER_H
#define COMMAND_ROUTER_H

#include "signer_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Dispatch and process a single received command message
 * @param msg Pointer to received message
 */
void command_router_dispatch(const message_t *msg);

#ifdef __cplusplus
}
#endif

#endif // COMMAND_ROUTER_H
