/*++

Copyright (c) PADL Software Pty Ltd, All rights reserved.

Module Name:

    ntapiext.cpp

Abstract:

    NTDLL extensions

Environment:

    Local Security Authority (LSA)

--*/

#include "TktBridgeAP.h"

NTSTATUS NTAPI
RtlDuplicateSid(OUT PSID *NewSid, IN PSID OriginalSid)
{
    NTSTATUS Status;
    ULONG SidLength;
    PSID Sid;

    *NewSid = nullptr;

    SidLength = RtlLengthSid(OriginalSid);

    Sid = RtlAllocateHeap(GetProcessHeap(), 0, SidLength);
    RETURN_NTSTATUS_IF_NULL_ALLOC(Sid);

    Status = RtlCopySid(SidLength, Sid, OriginalSid);
    RETURN_NTSTATUS_IF_NULL_ALLOC(Sid); // FIXME leaks

    *NewSid = Sid;

    return STATUS_SUCCESS;
}
