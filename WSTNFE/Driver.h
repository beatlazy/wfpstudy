/*++

Module Name:

    driver.h

Abstract:

    This file contains the driver definitions.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntddk.h>
#include <wdf.h>
#include <Fwpsk.h>
#include <Fwpmtypes.h>
#include <initguid.h>

#include <ntintsafe.h>                /// Inc
#include <ntstrsafe.h>                /// Inc

//#include <ntifs.h>
//#include <ntddk.h>
//#include <ndis.h>
//#include <fwpsk.h>
//#include <fwpmk.h>
//#include <wdm.h>

#include "device.h"
#include "queue.h"
#include "trace.h"

EXTERN_C_START

//
// WDFDRIVER Events
//

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD WSTNFEEvtDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP WSTNFEEvtDriverContextCleanup;

EXTERN_C_END


#define WSTNFE_TAG  (UINT32)"WNFE"

#define HLPR_NEW(pPtr,object,tag) \
for(;pPtr==0;					\
	)								\
{										\
	pPtr = (object *)ExAllocatePoolWithTag(NonPagedPoolNx,\
		sizeof(object),							\
		tag);				\
}

#define HLPR_DELETE(pPtr,tag)  \
if(pPtr)						\
{									\
	ExFreePoolWithTag((VOID *)pPtr, \
		tag);						\
}

/**
@macro="htonl"

Purpose:  Convert ULONG in Host Byte Order to Network Byte Order.                            <br>
<br>
Notes:                                                                                       <br>
<br>
MSDN_Ref:                                                                                    <br>
*/
#define htonl(l)                  \
   ((((l) & 0xFF000000) >> 24) | \
   (((l) & 0x00FF0000) >> 8)  |  \
   (((l) & 0x0000FF00) << 8)  |  \
   (((l) & 0x000000FF) << 24))

/**
@macro="htons"

Purpose:  Convert USHORT in Host Byte Order to Network Byte Order.                           <br>
<br>
Notes:                                                                                       <br>
<br>
MSDN_Ref:                                                                                    <br>
*/
#define htons(s) \
   ((((s) >> 8) & 0x00FF) | \
   (((s) << 8) & 0xFF00))

/**
@macro="ntohl"

Purpose:  Convert ULONG in Network Byte Order to Host Byte Order.                            <br>
<br>
Notes:                                                                                       <br>
<br>
MSDN_Ref:                                                                                    <br>
*/
#define ntohl(l)                   \
   ((((l) >> 24) & 0x000000FFL) | \
   (((l) >>  8) & 0x0000FF00L) |  \
   (((l) <<  8) & 0x00FF0000L) |  \
   (((l) << 24) & 0xFF000000L))

/**
@macro="ntohs"

Purpose:  Convert USHORT in Network Byte Order to Host Byte Order.                           <br>
<br>
Notes:                                                                                       <br>
<br>
MSDN_Ref:                                                                                    <br>
*/
#define ntohs(s)                     \
   ((USHORT)((((s) & 0x00ff) << 8) | \
   (((s) & 0xff00) >> 8)))


/**
@macro="HLPR_CLOSE_HANDLE"

Purpose:  Close a standard handle and set to 0.                                              <br>
<br>
Notes:                                                                                       <br>
<br>
MSDN_Ref:                                                                                    <br>
*/
#define HLPR_CLOSE_HANDLE(handle)\
   if(handle)                    \
   {                             \
      CloseHandle(handle);       \
      handle = 0;                \
   }

/**
@macro="HLPR_REG_CLOSE_KEY"

Purpose:  Close a registry handle and set to 0.                                              <br>
<br>
Notes:                                                                                       <br>
<br>
MSDN_Ref:                                                                                    <br>
*/
#define HLPR_REG_CLOSE_KEY(keyHandle) \
	if(keyHandle)                     \
	{									\
		RegCloseKey(keyHandle);				\
		keyHandle = 0;					\
	}


#define HLPR_NEW_ARRAY(pPtr,object,count,tag) \
for(;pPtr=0;)			\
{					\
	size_t SAFE_SIZE = 0;							\
	if (RtlSizeTMult(sizeof(object), (size_t)count, &SAFE_SIZE) == STATUS_SUCCESS &&     \
		SAFE_SIZE >= (sizeof(object)*count))		\
	{						\
		pPtr = (object *)ExAllocatePoolWithTag(NonPagedPoolNx, \
			SAFE_SIZE, \
			tag); \
			if (pPtr)	\
				RtlZeroMemory(pPtr,	\
					SAFE_SIZE);		\
	}					\
}			


#define HLPR_DELETE_ARRAY(pPtr, tag) \
   HLPR_DELETE(pPtr, tag)
