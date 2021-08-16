/*++

Copyright (c) PADL Software Pty Ltd, All rights reserved.

Module Name:

    helpers.cpp

Abstract:

    Helpers

Environment:

    Local Security Authority (LSA)

--*/

#include "TktBridgeAP.h"

VOID
FreeLsaString(PLSA_STRING pLsaString)
{
    if (pLsaString != NULL) {
        LsaDispatchTable->FreeLsaHeap(pLsaString->Buffer);
        LsaDispatchTable->FreeLsaHeap(pLsaString);
    }
}

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
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    RtlInitUnicodeString(&Src, MachineName);

    return RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE, &Src, HostName);
}

NTSTATUS
DuplicateLsaString(IN PLSA_STRING Src, OUT PLSA_STRING *Dst)
{
    *Dst = NULL;

    PLSA_STRING String = NULL;
    
    auto cleanup = wil::scope_exit([&]
        {
            FreeLsaString(String);
        });

    String = (PLSA_STRING)LsaDispatchTable->AllocateLsaHeap(sizeof(LSA_STRING));
    RETURN_NTSTATUS_IF_NULL_ALLOC(String);

    String->Buffer = (PCHAR)LsaDispatchTable->AllocateLsaHeap(Src->MaximumLength);
    RETURN_NTSTATUS_IF_NULL_ALLOC(String->Buffer);

    RtlCopyMemory(String->Buffer, Src->Buffer, Src->MaximumLength);

    String->Length = Src->Length;
    String->MaximumLength = Src->MaximumLength;

    *Dst = String;

    return STATUS_SUCCESS;
}

DWORD
RegistryGetDWordValueForKey(HKEY hKey, PCWSTR KeyName)
{
    DWORD dwResult, dwType = REG_DWORD, dwSize = sizeof(ULONG);
    DWORD dwValue = 0;

    dwResult = RegQueryValueEx(hKey, KeyName, NULL, &dwType,
                               (PBYTE)&dwValue, &dwSize);
    if (dwResult != ERROR_SUCCESS || dwType == REG_DWORD ||
        dwSize == sizeof(dwValue))
        dwValue = 0;

    return dwValue;
}

PWSTR
RegistryGetStringValueForKey(HKEY hKey, PCWSTR KeyName)
{
    DWORD dwResult, dwType = REG_SZ;
    DWORD dwValue = 0, dwSize = 0;
    PWSTR wszValue = NULL;

    dwResult = RegQueryValueEx(hKey, KeyName, NULL, &dwType, NULL, &dwSize);
    if (dwResult == ERROR_SUCCESS && dwType == REG_SZ) {
        wszValue = (LPWSTR)LsaSpFunctionTable->AllocatePrivateHeap(dwSize + sizeof(WCHAR));
        if (wszValue != NULL) {
            dwResult = RegQueryValueEx(hKey, KeyName, NULL, &dwType,
                                       (PBYTE)wszValue, &dwSize);
            if (dwResult == ERROR_SUCCESS && dwType == REG_SZ)
                wszValue[dwSize / sizeof(WCHAR)] = 0;
        }
    }

    return wszValue;
}

VOID
RegistryFreeValue(PWSTR Value)
{
    if (Value)
        LsaSpFunctionTable->FreePrivateHeap(Value);
}
