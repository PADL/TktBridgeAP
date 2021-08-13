#pragma once

extern "C" {

#define RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE			1
#define RTL_DUPLICATE_UNICODE_STRING_ALLOCATE_NULL_STRING	2

	NTSTATUS NTAPI
		RtlDuplicateUnicodeString(
			ULONG Flags,
			PCUNICODE_STRING StringIn,
			PUNICODE_STRING StringOut);

	BOOLEAN NTAPI
		RtlEqualUnicodeString(
			_In_ PCUNICODE_STRING String1,
			_In_ PCUNICODE_STRING String2,
			_In_ BOOLEAN CaseInSensitive
		);

	NTSTATUS NTAPI
		RtlDuplicateSid(OUT PSID* NewSid, IN PSID OriginalSid);

	VOID NTAPI
		RtlFreeSid(IN PSID Sid);

	ULONG NTAPI
		RtlLengthSid(
			PSID Sid
		);

	PVOID NTAPI
		RtlAllocateHeap(
			PVOID  HeapHandle,
			ULONG  Flags,
			SIZE_T Size
		);

	BOOLEAN NTAPI
		RtlFreeHeap(
			PVOID                 HeapHandle,
			ULONG                 Flags,
			_Frees_ptr_opt_ PVOID BaseAddress
		);

	NTSTATUS
		NTAPI RtlCopySid(
			ULONG DestinationSidLength,
			PSID  DestinationSid,
			PSID  SourceSid
		);

}