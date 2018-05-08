/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_WSTNFE,
    0x83cdf693,0x06d9,0x4bd7,0xaa,0x83,0xb9,0x5d,0xd4,0xe3,0xf5,0xf2);
// {83cdf693-06d9-4bd7-aa83-b95dd4e3f5f2}



// {2A7D2E58-5D11-4550-811E-0A29433FE90F}
DEFINE_GUID(GUID_REDIRECT_CALLOUT,
	0x2a7d2e58, 0x5d11, 0x4550, 0x81, 0x1e, 0xa, 0x29, 0x43, 0x3f, 0xe9, 0xf);


// {7FEEEDF7-BD33-462D-A94B-1AD0CAEB1859}
DEFINE_GUID(GUID_WSTNFE_SUBLAYER,
	0x7feeedf7, 0xbd33, 0x462d, 0xa9, 0x4b, 0x1a, 0xd0, 0xca, 0xeb, 0x18, 0x59);

// {ED6F2460-DA70-4EE6-82B9-8E63248C3BAB}
DEFINE_GUID(GUID_,
	0xed6f2460, 0xda70, 0x4ee6, 0x82, 0xb9, 0x8e, 0x63, 0x24, 0x8c, 0x3b, 0xab);
