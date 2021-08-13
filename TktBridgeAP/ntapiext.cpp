#include "TktBridgeAP.h"

NTSTATUS NTAPI
RtlDuplicateSid(OUT PSID *NewSid, IN PSID OriginalSid)
{
	NTSTATUS Status;
	ULONG SidLength;
	PSID Sid;

	SidLength = RtlLengthSid(OriginalSid);
	Sid = RtlAllocateHeap(GetProcessHeap(), 0, SidLength);
	if (Sid == NULL) {
		return STATUS_NO_MEMORY;
	}

	Status = RtlCopySid(SidLength, OriginalSid, Sid);
	if (!NT_SUCCESS(Status)) {
		RtlFreeHeap(GetProcessHeap(), 0, Sid);
		return Status;
	}

	*NewSid = Sid;
	return STATUS_SUCCESS;
}

