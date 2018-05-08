/*++

Module Name:

    device.h

Abstract:

    This file contains the device definitions.

Environment:

    Kernel-mode Driver Framework

--*/

#include "public.h"

EXTERN_C_START

//
// The device context performs the same job as
// a WDM device extension in the driver frameworks
//
typedef struct _DEVICE_CONTEXT
{
    ULONG PrivateDeviceData;  // just a placeholder

} DEVICE_CONTEXT, *PDEVICE_CONTEXT;


typedef struct PC_PROXY_DATA_
{
	UINT32  flags;
	BOOLEAN performInline;                  /// Inline vs. Out of Band
	BOOLEAN useWorkItems;                   /// Work Items vs. Deferred Procedure Calls
	BOOLEAN useThreadedDPC;                 /// Threaded DPCs vs Deferred Procedure Calls
	BOOLEAN proxyToRemoteService;           /// Local vs. Remote Service
	BYTE    pReserved[7];
	UINT8   ipVersion;
	union
	{
		BYTE pIPv4[4];                       /// Network Byte Order
		BYTE pIPv6[16];
		BYTE pBytes[16];
	}proxyLocalAddress;
	union
	{
		BYTE pIPv4[4];                       /// Network Byte Order
		BYTE pIPv6[16];
		BYTE pBytes[16];
	}proxyRemoteAddress;
	UINT32  localScopeId;
	UINT32  remoteScopeId;
	UINT16  proxyLocalPort;                 /// Network Byte Order
	UINT16  proxyRemotePort;                /// Network Byte Order
	UINT32  targetProcessID;
	UINT64  tcpPortReservationToken;
	UINT64  udpPortReservationToken;

} PC_PROXY_DATA, *PPC_PROXY_DATA;



typedef struct REDIRECT_DATA_
{
	UINT64             classifyHandle;

#if(NTDDI_VERSION >= NTDDI_WIN8)

	HANDLE             redirectHandle;

#endif /// (NTDDI_VERSION >= NTDDI_WIN8)

	VOID*              pWritableLayerData; /// FWPS_BIND_REQUEST or FWPS_CONNECT_REQUEST
	PC_PROXY_DATA*     pProxyData;
	FWPS_CLASSIFY_OUT* pClassifyOut;
	BOOLEAN            isPended;
	BYTE               pReserved[7];
}REDIRECT_DATA, *PREDIRECT_DATA;

typedef struct CLASSIFY_DATA_
{
	const FWPS_INCOMING_VALUES*          pClassifyValues;
	const FWPS_INCOMING_METADATA_VALUES* pMetadataValues;
	VOID*                                pPacket;               /// NET_BUFFER_LIST | FWPS_STREAM_CALLOUT_IO_PACKET
	const VOID*                          pClassifyContext;
	const FWPS_FILTER*                   pFilter;
	UINT64                               flowContext;
	FWPS_CLASSIFY_OUT*                   pClassifyOut;
	UINT64                               classifyContextHandle;
	BOOLEAN                              chainedNBL;
	UINT32                               numChainedNBLs;
}CLASSIFY_DATA, *PCLASSIFY_DATA;

//
// This macro will generate an inline function called DeviceGetContext
// which will be used to get a pointer to the device context memory
// in a type safe manner.
//
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, DeviceGetContext)

//
// Function to initialize the device and its callbacks
//
NTSTATUS
WSTNFECreateDevice(
    _Inout_ PWDFDEVICE_INIT DeviceInit
    );

EXTERN_C_END
