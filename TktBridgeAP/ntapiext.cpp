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
RtlDuplicateSid(_Out_ PSID *DestinationSid, _In_ PSID SourceSid)
{
    NTSTATUS Status;
    ULONG SidLength;
    PSID Sid;

    *DestinationSid = nullptr;

    if (SourceSid == nullptr)
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    SidLength = RtlLengthSid(SourceSid);

    Sid = RtlAllocateHeap(GetProcessHeap(), 0, SidLength);
    RETURN_NTSTATUS_IF_NULL_ALLOC(Sid);

    Status = RtlCopySid(SidLength, Sid, SourceSid);
    if (!NT_SUCCESS(Status))
        RtlFreeSid(Sid);
    RETURN_NTSTATUS_IF_NULL_ALLOC(Sid);

    *DestinationSid = Sid;

    return STATUS_SUCCESS;
}
