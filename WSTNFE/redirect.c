#include "Driver.h"
//#include <ntifs.h>
#include <ntddk.h>
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <wdm.h>

#include <MSTCPIP.h>       /// Include\Shared


HANDLE gEngineHandle;

UINT32  gAleConnectCalloutIdV4;

NTSTATUS NTAPI WSTNFE_NotifyFn1(
	_In_       FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID                     *filterKey,
	_In_ const FWPS_FILTER1             *filter
);

NTSTATUS PerformProxyConnectRedirection(_In_ CLASSIFY_DATA** ppClassifyData,
	_Inout_ REDIRECT_DATA** ppRedirectData);


VOID ClassifyProxyByALERedirect(_In_ const FWPS_INCOMING_VALUES* pClassifyValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* pMetadata,
	_Inout_opt_ VOID* pLayerData,
	_In_opt_ const VOID* pClassifyContext,
	_In_ const FWPS_FILTER* pFilter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* pClassifyOut);

void
SFDeregistryCallouts(
	__in PDEVICE_OBJECT DeviceObject
);

NTSTATUS
SFRegisterALEClassifyCallouts(
	__in const GUID* layerKey,
	__in const GUID* calloutKey,
	__in void* DeviceObject,
	__out UINT32* calloutId
);

NTSTATUS SFAddFilter(
	__in const wchar_t* filterName,
	__in const wchar_t* filterDesc,
	__in const GUID* layerKey,
	__in const GUID* calloutKey
);

inline VOID KrnlHlprRedirectDataPurge(_Inout_ REDIRECT_DATA* pRedirectData)
{
#if DBG

	DbgPrintEx(DPFLTR_IHVNETWORK_ID,
		DPFLTR_INFO_LEVEL,
		" ---> KrnlHlprRedirectDataPurge()\n");

#endif /// DBG

	NT_ASSERT(pRedirectData);

	if (pRedirectData->pWritableLayerData)
	{
		FwpsApplyModifiedLayerData(pRedirectData->classifyHandle,
			pRedirectData->pWritableLayerData,
			FWPS_CLASSIFY_FLAG_REAUTHORIZE_IF_MODIFIED_BY_OTHERS);

		pRedirectData->pWritableLayerData = 0;
	}

	if (pRedirectData->classifyHandle)
	{
		if (pRedirectData->isPended)
		{
			FwpsCompleteClassify(pRedirectData->classifyHandle,
				0,
				pRedirectData->pClassifyOut);

			pRedirectData->isPended = FALSE;
		}

#if(NTDDI_VERSION >= NTDDI_WIN8)

		if (pRedirectData->redirectHandle)
		{
			FwpsRedirectHandleDestroy(pRedirectData->redirectHandle);

			pRedirectData->redirectHandle = 0;
		}

#endif

		FwpsReleaseClassifyHandle(pRedirectData->classifyHandle);
		pRedirectData->classifyHandle = 0;
	}
	RtlZeroMemory(pRedirectData,
		sizeof(REDIRECT_DATA));

#if DBG

	DbgPrintEx(DPFLTR_IHVNETWORK_ID,
		DPFLTR_INFO_LEVEL,
		" <--- KrnlHlprRedirectDataPurge()\n");

#endif /// DBG

	return;
}


inline VOID KrnlHlprRedirectDataDestroy(_Inout_ REDIRECT_DATA** ppRedirectData)
{
#if DBG

	DbgPrintEx(DPFLTR_IHVNETWORK_ID,
		DPFLTR_INFO_LEVEL,
		" ---> KrnlHlprRedirectDataDestroy()\n");

#endif /// DBG

	NT_ASSERT(ppRedirectData);

	if (*ppRedirectData)
	{
		KrnlHlprRedirectDataPurge(*ppRedirectData);

		HLPR_DELETE(*ppRedirectData,
			WSTNFE_TAG);
	}

#if DBG

	DbgPrintEx(DPFLTR_IHVNETWORK_ID,
		DPFLTR_INFO_LEVEL,
		" <--- KrnlHlprRedirectDataDestroy()\n");

#endif /// DBG

	return;
}


NTSTATUS
SFRegistryCallouts(
	__in PDEVICE_OBJECT DeviceObject
)
{
	NTSTATUS        Status = STATUS_SUCCESS;
	BOOLEAN         EngineOpened = FALSE;
	BOOLEAN         InTransaction = FALSE;
	FWPM_SESSION0   Session = { 0 };
	FWPM_SUBLAYER0  FirewallSubLayer;

	Session.flags = FWPM_SESSION_FLAG_DYNAMIC;

	Status = FwpmEngineOpen0(NULL,
		RPC_C_AUTHN_WINNT,
		NULL,
		&Session,
		&gEngineHandle);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

	EngineOpened = TRUE;

	Status = FwpmTransactionBegin0(gEngineHandle, 0);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

	InTransaction = TRUE;

	RtlZeroMemory(&FirewallSubLayer, sizeof(FWPM_SUBLAYER0));

	FirewallSubLayer.subLayerKey = GUID_WSTNFE_SUBLAYER;
	FirewallSubLayer.displayData.name = L"Transport SimpleFirewall Sub-Layer";
	FirewallSubLayer.displayData.description = L"Sub-Layer for use by Transport SimpleFirewall callouts";
	FirewallSubLayer.flags = 0;
	FirewallSubLayer.weight = 0;

	Status = FwpmSubLayerAdd0(gEngineHandle, &FirewallSubLayer, NULL);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

	Status = SFRegisterALEClassifyCallouts(&FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
		&GUID_REDIRECT_CALLOUT,
		DeviceObject,
		&gAleConnectCalloutIdV4);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

#if 0
	Status = SFRegisterALEClassifyCallouts(&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
		&SF_ALE_RECV_ACCEPT_CALLOUT_V4,
		DeviceObject,
		&gAleRecvAcceptCalloutIdV4);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}
#endif


	Status = FwpmTransactionCommit0(gEngineHandle);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

	InTransaction = FALSE;

Exit:

	if (!NT_SUCCESS(Status))
	{
		if (InTransaction)
		{
			FwpmTransactionAbort0(gEngineHandle);
		}

		if (EngineOpened)
		{
			FwpmEngineClose0(gEngineHandle);
			gEngineHandle = NULL;
		}
	}

	return Status;
}


	
void
SFDeregistryCallouts(
	__in PDEVICE_OBJECT DeviceObject
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	FwpmEngineClose0(gEngineHandle);
	gEngineHandle = NULL;

	FwpsCalloutUnregisterById0(gAleConnectCalloutIdV4);
	//FwpsCalloutUnregisterById0(gAleRecvAcceptCalloutIdV4);
}

NTSTATUS
SFRegisterALEClassifyCallouts(
	__in const GUID* layerKey,
	__in const GUID* calloutKey,
	__in void* DeviceObject,
	__out UINT32* calloutId
)
{
	NTSTATUS Status = STATUS_SUCCESS;

	FWPS_CALLOUT sCallout = { 0 };
	FWPM_CALLOUT mCallout = { 0 };

	FWPM_DISPLAY_DATA0 DisplayData = { 0 };

	BOOLEAN calloutRegistered = FALSE;

	sCallout.calloutKey = *calloutKey;

	if (IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V4))
	{
		sCallout.classifyFn = ClassifyProxyByALERedirect;
		//sCallout.notifyFn = WSTNFE_NotifyFn1;
	}
	else
	{
		//sCallout.classifyFn = SFALERecvAcceptClassify;
		//sCallout.notifyFn = SFALERecvAcceptNotify;
	}

	Status = FwpsCalloutRegister(DeviceObject,
		&sCallout,
		calloutId);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

	calloutRegistered = TRUE;

	DisplayData.name = L"Transport SimpleFirewall ALE Classify Callout";
	DisplayData.description = L"Intercepts inbound or outbound connect attempts";

	mCallout.calloutKey = *calloutKey;


	Status = FwpmCalloutAdd(gEngineHandle,
		&mCallout,
		NULL,
		NULL);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

	Status = SFAddFilter(L"Transport SimpleFirewall ALE Classify",
		L"Intercepts inbound or outbound connect attempts",
		layerKey,
		calloutKey);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

Exit:

	if (!NT_SUCCESS(Status))
	{
		if (calloutRegistered)
		{
			FwpsCalloutUnregisterById0(*calloutId);
			*calloutId = 0;
		}
	}

	return Status;
}
NTSTATUS SFAddFilter(
	__in const wchar_t* filterName,
	__in const wchar_t* filterDesc,
	__in const GUID* layerKey,
	__in const GUID* calloutKey
)
{
	FWPM_FILTER0 Filter = { 0 };

	Filter.layerKey = *layerKey;
	Filter.displayData.name = (wchar_t*)filterName;
	Filter.displayData.description = (wchar_t*)filterDesc;

	Filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	Filter.action.calloutKey = *calloutKey;
	Filter.subLayerKey = GUID_WSTNFE_SUBLAYER;
	Filter.weight.type = FWP_EMPTY;
	Filter.rawContext = 0;

	return FwpmFilterAdd0(gEngineHandle, &Filter, NULL, NULL);
}


VOID ClassifyProxyByALERedirect(_In_ const FWPS_INCOMING_VALUES* pClassifyValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* pMetadata,
	_Inout_opt_ VOID* pLayerData,
	_In_opt_ const VOID* pClassifyContext,
	_In_ const FWPS_FILTER* pFilter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* pClassifyOut)
{
	NT_ASSERT(pClassifyValues);
	NT_ASSERT(pMetadata);
	NT_ASSERT(pLayerData);
	NT_ASSERT(pClassifyContext);
	NT_ASSERT(pFilter);
	NT_ASSERT(pClassifyOut);
	NT_ASSERT(pClassifyValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4 ||
		pClassifyValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V6 ||
		pClassifyValues->layerId == FWPS_LAYER_ALE_BIND_REDIRECT_V4 ||
		pClassifyValues->layerId == FWPS_LAYER_ALE_BIND_REDIRECT_V6);
	NT_ASSERT(pFilter->providerContext);
	NT_ASSERT(pFilter->providerContext->type == FWPM_GENERAL_CONTEXT);
	NT_ASSERT(pFilter->providerContext->dataBuffer);
	NT_ASSERT(pFilter->providerContext->dataBuffer->size == sizeof(PC_PROXY_DATA));
	NT_ASSERT(pFilter->providerContext->dataBuffer->data);







}

/*
NTSTATUS NTAPI WSTNFE_NotifyFn1(
	_In_       FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID                     *filterKey,
	_In_ const FWPS_FILTER1             *filter
)
{
	return STATUS_SUCCESS;

}
*/



NTSTATUS KrnlHlprRedirectDataPopulate(_Inout_ REDIRECT_DATA* pRedirectData,
	_In_ const VOID* pClassifyContext,
	_In_ const FWPS_FILTER* pFilter,
	_In_ FWPS_CLASSIFY_OUT* pClassifyOut)
{
#if DBG

	DbgPrintEx(DPFLTR_IHVNETWORK_ID,
		DPFLTR_INFO_LEVEL,
		" ---> KrnlHlprRedirectDataPopulate()\n");

#endif /// DBG

	NT_ASSERT(pRedirectData);
	NT_ASSERT(pClassifyContext);
	NT_ASSERT(pFilter);
	NT_ASSERT(pClassifyOut);
	NT_ASSERT(pFilter->providerContext);
	NT_ASSERT(pFilter->providerContext->type == FWPM_GENERAL_CONTEXT);
	NT_ASSERT(pFilter->providerContext->dataBuffer);
	NT_ASSERT(pFilter->providerContext->dataBuffer->size == sizeof(PC_PROXY_DATA));
	NT_ASSERT(pFilter->providerContext->dataBuffer->data);

	NTSTATUS status = STATUS_SUCCESS;

	status = FwpsAcquireClassifyHandle((void*)pClassifyContext,
		0,
		&(pRedirectData->classifyHandle));
	if (status != STATUS_SUCCESS)
	{
		DbgPrintEx(DPFLTR_IHVNETWORK_ID,
			DPFLTR_ERROR_LEVEL,
			" !!!! KrnlHlprRedirectDataPopulate : FwpsAcquireClassifyHandle() [status: %#x]\n",
			status);

		//HLPR_BAIL;
	}

#if(NTDDI_VERSION >= NTDDI_WIN8)

	status = FwpsRedirectHandleCreate(&GUID_WSTNFE_PROVIDER,
		0,
		&(pRedirectData->redirectHandle));
	if (status != STATUS_SUCCESS)
	{
		DbgPrintEx(DPFLTR_IHVNETWORK_ID,
			DPFLTR_ERROR_LEVEL,
			" !!!! KrnlHlprRedirectDataPopulate : FwpsRedirectHandleCreate() [status: %#x]\n",
			status);

		//HLPR_BAIL;
	}

#endif

	status = FwpsAcquireWritableLayerDataPointer(pRedirectData->classifyHandle,
		pFilter->filterId,
		0,
		&(pRedirectData->pWritableLayerData),
		pClassifyOut);
	if (status != STATUS_SUCCESS)
	{
		DbgPrintEx(DPFLTR_IHVNETWORK_ID,
			DPFLTR_ERROR_LEVEL,
			" !!!! KrnlHlprRedirectDataPopulate : FwpsAcquireWritableLayerDataPointer() [status: %#x]\n",
			status);

		//HLPR_BAIL;
	}

	pRedirectData->pProxyData = (PC_PROXY_DATA*)pFilter->providerContext->dataBuffer->data;

HLPR_BAIL_LABEL:

	if (status != STATUS_SUCCESS)
		KrnlHlprRedirectDataPurge(pRedirectData);

#if DBG

	DbgPrintEx(DPFLTR_IHVNETWORK_ID,
		DPFLTR_INFO_LEVEL,
		" <--- KrnlHlprRedirectDataPopulate() [status: %#x]\n",
		status);

#endif /// DBG

	return status;
}

NTSTATUS KrnlHlprRedirectDataCreate(_Outptr_ REDIRECT_DATA** ppRedirectData,
	_In_ const VOID* pClassifyContext,
	_In_ const FWPS_FILTER* pFilter,
	_In_ FWPS_CLASSIFY_OUT* pClassifyOut)
{
#if DBG

	DbgPrintEx(DPFLTR_IHVNETWORK_ID,
		DPFLTR_INFO_LEVEL,
		" ---> KrnlHlprRedirectDataCreate()\n");

#endif /// DBG

	NT_ASSERT(ppRedirectData);
	NT_ASSERT(pClassifyContext);
	NT_ASSERT(pFilter);
	NT_ASSERT(pClassifyOut);

	NTSTATUS status = STATUS_SUCCESS;

	HLPR_NEW(*ppRedirectData,
		REDIRECT_DATA,
		WSTNFE_TAG);
	//HLPR_BAIL_ON_ALLOC_FAILURE(*ppRedirectData,
	//	status);

	status = KrnlHlprRedirectDataPopulate(*ppRedirectData,
		pClassifyContext,
		pFilter,
		pClassifyOut);

HLPR_BAIL_LABEL:

#pragma warning(push)
#pragma warning(disable: 6001) /// *ppRedirectData initialized with call to HLPR_NEW & KrnlHlprRedirectDataPopulate 

	if (status != STATUS_SUCCESS &&
		*ppRedirectData)
		KrnlHlprRedirectDataDestroy(ppRedirectData);

#pragma warning(pop)

#if DBG

	DbgPrintEx(DPFLTR_IHVNETWORK_ID,
		DPFLTR_INFO_LEVEL,
		" <--- KrnlHlprRedirectDataCreate() [status: %#x]\n",
		status);

#endif /// DBG

	return status;
}

NTSTATUS TriggerProxyByALERedirectInline(_In_ const FWPS_INCOMING_VALUES* pClassifyValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* pMetadata,
	_Inout_ VOID* pLayerData,
	_In_opt_ const VOID* pClassifyContext,
	_In_ const FWPS_FILTER* pFilter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* pClassifyOut,
	_Inout_ REDIRECT_DATA** ppRedirectData)
{
#if DBG

	DbgPrintEx(DPFLTR_IHVNETWORK_ID,
		DPFLTR_INFO_LEVEL,
		" ---> TriggerProxyByALERedirectInline()\n");

#endif /// DBG

	NT_ASSERT(pClassifyValues);
	NT_ASSERT(pMetadata);
	NT_ASSERT(pLayerData);
	NT_ASSERT(pFilter);
	NT_ASSERT(pClassifyOut);
	NT_ASSERT(ppRedirectData);
	NT_ASSERT(*ppRedirectData);

	NTSTATUS       status = STATUS_SUCCESS;
	CLASSIFY_DATA* pClassifyData = 0;

	HLPR_NEW(pClassifyData,
		CLASSIFY_DATA,
		WSTNFE_TAG);
	//HLPR_BAIL_ON_ALLOC_FAILURE(pClassifyData,
	//	status);

	pClassifyData->pClassifyValues = pClassifyValues;
	pClassifyData->pMetadataValues = pMetadata;
	pClassifyData->pPacket = pLayerData;
	pClassifyData->pClassifyContext = pClassifyContext;
	pClassifyData->pFilter = pFilter;
	pClassifyData->flowContext = flowContext;
	pClassifyData->pClassifyOut = pClassifyOut;

	(*ppRedirectData)->pClassifyOut = pClassifyOut;

	if (pClassifyValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4 ||
		pClassifyValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V6)
		status = PerformProxyConnectRedirection(&pClassifyData,
			ppRedirectData);
	/*
	else if (pClassifyValues->layerId == FWPS_LAYER_ALE_BIND_REDIRECT_V4 ||
		pClassifyValues->layerId == FWPS_LAYER_ALE_BIND_REDIRECT_V6)
		status = PerformProxySocketRedirection(&pClassifyData,
			ppRedirectData);

	*/


HLPR_BAIL_LABEL:

	HLPR_DELETE(pClassifyData,
		WSTNFE_TAG);

#if DBG

	DbgPrintEx(DPFLTR_IHVNETWORK_ID,
		DPFLTR_INFO_LEVEL,
		" <--- TriggerProxyByALERedirectInline() [status: %#x]\n",
		status);

#endif /// DBG

	return status;
}

NTSTATUS PerformProxyConnectRedirection(_In_ CLASSIFY_DATA** ppClassifyData,
	_Inout_ REDIRECT_DATA** ppRedirectData)
{
#if DBG

	DbgPrintEx(DPFLTR_IHVNETWORK_ID,
		DPFLTR_INFO_LEVEL,
		" ---> PerformProxyConnectRedirection()\n");

#endif /// DBG

	NT_ASSERT(ppClassifyData);
	NT_ASSERT(ppRedirectData);
	NT_ASSERT(*ppClassifyData);
	NT_ASSERT(*ppRedirectData);

	NTSTATUS              status = STATUS_SUCCESS;
	FWPS_CONNECT_REQUEST* pConnectRequest = (FWPS_CONNECT_REQUEST*)(*ppRedirectData)->pWritableLayerData;
	UINT32                actionType = FWP_ACTION_PERMIT;
	FWPS_INCOMING_VALUES* pClassifyValues = (FWPS_INCOMING_VALUES*)(*ppClassifyData)->pClassifyValues;
	FWP_VALUE*            pProtocolValue = 0;
	UINT8                 ipProtocol = 0;

#if(NTDDI_VERSION >= NTDDI_WIN8)

	SOCKADDR_STORAGE*     pSockAddrStorage = 0;

	if ((*ppRedirectData)->redirectHandle)
		pConnectRequest->localRedirectHandle = (*ppRedirectData)->redirectHandle;

	HLPR_NEW_ARRAY(pSockAddrStorage,
		SOCKADDR_STORAGE,
		2,
		WSTNFE_TAG);
//	HLPR_BAIL_ON_ALLOC_FAILURE(pSockAddrStorage,
//		status);

	/// Pass original remote destination values to query them in user mode
	RtlCopyMemory(&(pSockAddrStorage[0]),
		&(pConnectRequest->remoteAddressAndPort),
		sizeof(SOCKADDR_STORAGE));

	RtlCopyMemory(&(pSockAddrStorage[1]),
		&(pConnectRequest->localAddressAndPort),
		sizeof(SOCKADDR_STORAGE));

	/// WFP will take ownership of this memory and free it when the flow / redirection terminates
	pConnectRequest->localRedirectContext = pSockAddrStorage;
	pConnectRequest->localRedirectContextSize = sizeof(SOCKADDR_STORAGE) * 2;

#endif /// (NTDDI_VERSION >= NTDDI_WIN8)

	//pProtocolValue = KrnlHlprFwpValueGetFromFwpsIncomingValues(pClassifyValues,
	//	&FWPM_CONDITION_IP_PROTOCOL);
	//if (pProtocolValue)
	//	ipProtocol = pProtocolValue->uint8;

	/// For non-TCP, this setting will not be enforced being that local redirection of this tuple is only 
	/// available during bind time. and ideally redirection should be performed using ALE_BIND_REDIRECT instead.
	if ((*ppRedirectData)->pProxyData->flags & PCPDF_PROXY_LOCAL_ADDRESS)
		INETADDR_SET_ADDRESS((PSOCKADDR)&(pConnectRequest->localAddressAndPort),
		(*ppRedirectData)->pProxyData->proxyLocalAddress.pBytes);

	/// For non-TCP, this setting will not be enforced being that local redirection of this tuple is only 
	/// available during bind time. and ideally redirection should be performed using ALE_BIND_REDIRECT instead.
	if ((*ppRedirectData)->pProxyData->flags & PCPDF_PROXY_LOCAL_PORT)
		INETADDR_SET_PORT((PSOCKADDR)&(pConnectRequest->localAddressAndPort),
		(*ppRedirectData)->pProxyData->proxyLocalPort);

	if ((*ppRedirectData)->pProxyData->flags & PCPDF_PROXY_REMOTE_ADDRESS)
	{
		if ((*ppRedirectData)->pProxyData->proxyToRemoteService)
			INETADDR_SET_ADDRESS((PSOCKADDR)&(pConnectRequest->remoteAddressAndPort),
			(*ppRedirectData)->pProxyData->proxyRemoteAddress.pBytes);
		else
		{
			/// Ensure we don't need to worry about crossing any of the TCP/IP stack's zones
			if (INETADDR_ISANY((PSOCKADDR)&(pConnectRequest->localAddressAndPort)))
				INETADDR_SETLOOPBACK((PSOCKADDR)&(pConnectRequest->remoteAddressAndPort));
			else
				INETADDR_SET_ADDRESS((PSOCKADDR)&(pConnectRequest->remoteAddressAndPort),
					INETADDR_ADDRESS((PSOCKADDR)&(pConnectRequest->localAddressAndPort)));
		}
	}

	if ((*ppRedirectData)->pProxyData->flags & PCPDF_PROXY_REMOTE_PORT)
		INETADDR_SET_PORT((PSOCKADDR)&(pConnectRequest->remoteAddressAndPort),
		(*ppRedirectData)->pProxyData->proxyRemotePort);

	if (ipProtocol == IPPROTO_TCP)
		pConnectRequest->portReservationToken = (*ppRedirectData)->pProxyData->tcpPortReservationToken;
	else if (ipProtocol == IPPROTO_UDP)
		pConnectRequest->portReservationToken = (*ppRedirectData)->pProxyData->udpPortReservationToken;

	if ((*ppRedirectData)->pProxyData->targetProcessID)
		pConnectRequest->localRedirectTargetPID = (*ppRedirectData)->pProxyData->targetProcessID;

#if(NTDDI_VERSION >= NTDDI_WIN8)

	HLPR_BAIL_LABEL:

				   if (status != STATUS_SUCCESS)
				   {
					   actionType = FWP_ACTION_BLOCK;

					   HLPR_DELETE_ARRAY(pSockAddrStorage,
						   WSTNFE_TAG);
				   }

#endif /// (NTDDI_VERSION >= NTDDI_WIN8)

#pragma warning(push)
#pragma warning(disable: 6001) /// *ppRedirectData has already been initialized in previous call to KrnlHlprRedirectDataCreate

				   (*ppRedirectData)->pClassifyOut->actionType = actionType;

				   /// This will apply the modified data and cleanup the classify handle
				   KrnlHlprRedirectDataDestroy(ppRedirectData);

#pragma warning(pop)

#if DBG

				   DbgPrintEx(DPFLTR_IHVNETWORK_ID,
					   DPFLTR_INFO_LEVEL,
					   " <--- PerformProxyConnectRedirection() [status:%#x]\n",
					   status);

#endif /// DBG

				   return status;
}
