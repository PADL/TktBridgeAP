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
FreeLsaString(_Inout_ PLSA_STRING pLsaString)
{
    if (pLsaString != nullptr) {
        LsaDispatchTable->FreeLsaHeap(pLsaString->Buffer);
        LsaDispatchTable->FreeLsaHeap(pLsaString);
    }
}

BOOLEAN
IsLocalHost(_In_ PUNICODE_STRING HostName)
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
GetLocalHostName(_In_ BOOLEAN bLsaAlloc,
                 _Inout_ PUNICODE_STRING HostName)
{
    WCHAR MachineName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD cchMachineName = sizeof(MachineName) / 2;
    UNICODE_STRING Src;

    if (!GetComputerName(MachineName, &cchMachineName))
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);

    RtlInitUnicodeString(&Src, MachineName);

    return RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
                                     &Src, HostName);
}

NTSTATUS
DuplicateLsaString(_In_ PLSA_STRING Src,
                   _Out_ PLSA_STRING *Dst)
{
    *Dst = nullptr;

    PLSA_STRING String = nullptr;
    
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
RegistryGetDWordValueForKey(_In_ HKEY hKey,
                            _In_z_ PCWSTR KeyName)
{
    DWORD dwResult, dwType = REG_DWORD, dwSize = sizeof(ULONG);
    DWORD dwValue = 0;

    dwResult = RegQueryValueEx(hKey, KeyName, nullptr, &dwType,
                               (PBYTE)&dwValue, &dwSize);
    if (dwResult != ERROR_SUCCESS || dwType == REG_DWORD ||
        dwSize == sizeof(dwValue))
        dwValue = 0;

    return dwValue;
}

PWSTR
RegistryGetStringValueForKey(_In_ HKEY hKey,
                             _In_z_ PCWSTR KeyName)
{
    DWORD dwResult, dwType = REG_SZ;
    DWORD dwValue = 0, dwSize = 0;
    PWSTR wszValue = nullptr;

    dwResult = RegQueryValueEx(hKey, KeyName, nullptr, &dwType, nullptr, &dwSize);
    if (dwResult == ERROR_SUCCESS && dwType == REG_SZ) {
        wszValue = (LPWSTR)WIL_AllocateMemory(dwSize + sizeof(WCHAR));
        if (wszValue != nullptr) {
            dwResult = RegQueryValueEx(hKey, KeyName, nullptr, &dwType,
                                       (PBYTE)wszValue, &dwSize);
            if (dwResult == ERROR_SUCCESS && dwType == REG_SZ)
                wszValue[dwSize / sizeof(WCHAR)] = 0;
        }
    }

    return wszValue;
}

NTSTATUS
UnicodeToUTF8Alloc(_In_ PCWSTR wszUnicodeString,
                   _Out_ PCHAR *pszUTF8String)
{
    NTSTATUS Status;
    ULONG cbUTF8String = 0;
    ULONG cbUnicodeString = (wcslen(wszUnicodeString) + 1) * sizeof(WCHAR);

    *pszUTF8String = nullptr;

    Status = RtlUnicodeToUTF8N(nullptr, 0, &cbUTF8String, wszUnicodeString, cbUnicodeString);
    RETURN_IF_NTSTATUS_FAILED(Status);

    *pszUTF8String = (PCHAR)WIL_AllocateMemory(cbUTF8String);
    RETURN_NTSTATUS_IF_NULL_ALLOC(*pszUTF8String);

    Status = RtlUnicodeToUTF8N(*pszUTF8String, cbUTF8String, &cbUTF8String,
                               wszUnicodeString, cbUnicodeString);
    RETURN_IF_NTSTATUS_FAILED(Status);

    return STATUS_SUCCESS;
}

NTSTATUS
UTF8ToUnicodeAlloc(_In_ const PCHAR szUTF8String,
    _Out_ PWSTR* pwszUnicodeString)
{
    NTSTATUS Status;
    ULONG cbUnicodeString = 0;
    ULONG cbUTF8String = strlen(szUTF8String) + 1;

    *pwszUnicodeString = nullptr;

    Status = RtlUTF8ToUnicodeN(nullptr, 0, &cbUnicodeString, szUTF8String, cbUTF8String);
    RETURN_IF_NTSTATUS_FAILED(Status);

    *pwszUnicodeString = (PWSTR)WIL_AllocateMemory(cbUnicodeString);
    RETURN_NTSTATUS_IF_NULL_ALLOC(*pwszUnicodeString);

    Status = RtlUTF8ToUnicodeN(*pwszUnicodeString, cbUnicodeString, &cbUnicodeString,
        szUTF8String, cbUTF8String);
    RETURN_IF_NTSTATUS_FAILED(Status);

    return STATUS_SUCCESS;
}
