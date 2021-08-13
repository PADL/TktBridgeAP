#include "TktBridgeAP.h"

NTSTATUS NTAPI
RtlDuplicateSid(OUT PSID *NewSid, IN PSID OriginalSid)
{
    NTSTATUS Status;
    ULONG SidLength;
    unique_rtl_sid Sid;

    SidLength = RtlLengthSid(OriginalSid);
    Sid = RtlAllocateHeap(GetProcessHeap(), 0, SidLength);
    RETURN_NTSTATUS_IF_NULL_ALLOC(Sid);

    Status = RtlCopySid(SidLength, OriginalSid, Sid);
    RETURN_NTSTATUS_IF_NULL_ALLOC(Sid);

    *NewSid = Sid;
    return STATUS_SUCCESS;
}
