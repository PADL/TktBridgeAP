#include "TktBridgeAP.h"

BOOLEAN
IsLocalHost(PUNICODE_STRING HostName)
{
    WCHAR MachineName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD cchMachineName = sizeof(MachineName) / 2;
    UNICODE_STRING Src;

    if (!GetComputerName(MachineName, &cchMachineName))
        return FALSE;

    RtlInitUnicodeString(&Src, MachineName);

    return RtlEqualUnicodeString(HostName, &Src, TRUE);
}

NTSTATUS
GetLocalHostName(BOOLEAN bLsaAlloc, PUNICODE_STRING HostName)
{
    WCHAR MachineName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD cchMachineName = sizeof(MachineName) / 2;
    UNICODE_STRING Src;

    if (!GetComputerName(MachineName, &cchMachineName))
        return STATUS_INVALID_PARAMETER;

    RtlInitUnicodeString(&Src, MachineName);

    return RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE, &Src, HostName);
}