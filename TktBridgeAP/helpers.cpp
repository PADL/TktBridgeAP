/*
 * Copyright (c) 2021, PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of PADL Software nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "TktBridgeAP.h"

VOID
Seconds64Since1970ToTime(_In_ ULONG64 ElapsedSeconds,
                         _Out_ PLARGE_INTEGER Time)
{
    // Don't use RtlSecondsSince1970ToTime as it's not 2038 compliant
    ULONG64 const SecondsToStartOf1970 = 0x2b6109100;
    ULONG64 const HundredNanoSecondsInSecond = 10000000LL;

    Time->QuadPart = (ElapsedSeconds + SecondsToStartOf1970) * HundredNanoSecondsInSecond;
}

ULONG
GetCallAttributes(VOID)
{
    SECPKG_CALL_INFO CallInfo;

    if (LsaSpFunctionTable == nullptr)
        return 0;

    if (!LsaSpFunctionTable->GetCallInfo(&CallInfo))
        return 0;

    return CallInfo.Attributes;
}

bool
IsLocalHost(_In_ PUNICODE_STRING HostName)
{
    WCHAR MachineName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD cchMachineName = sizeof(MachineName) / sizeof(WCHAR);
    UNICODE_STRING MachineNameUS;

    if (!GetComputerName(MachineName, &cchMachineName))
        return FALSE;

    RtlInitUnicodeString(&MachineNameUS, MachineName);

    return RtlEqualUnicodeString(HostName, &MachineNameUS, TRUE);
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

    dwResult = RegQueryValueEx(hKey, KeyName, nullptr, &dwType,
                               nullptr, &dwSize);
    if (dwResult != ERROR_SUCCESS || dwType != REG_SZ)
        return nullptr;

    wszValue = (PWSTR)WIL_AllocateMemory(dwSize + sizeof(WCHAR));
    if (wszValue == nullptr)
        return nullptr;

    dwResult = RegQueryValueEx(hKey, KeyName, nullptr, &dwType,
                               (PBYTE)wszValue, &dwSize);
    if (dwResult != ERROR_SUCCESS || dwType != REG_SZ) {
        WIL_FreeMemory(wszValue);
        return nullptr;
    }

    wszValue[dwSize / sizeof(WCHAR)] = L'\0';

    return wszValue;
}

PWSTR *
RegistryGetStringValuesForKey(_In_ HKEY hKey,
                              _In_z_ PCWSTR KeyName)
{
    DWORD dwResult, dwType = REG_SZ;
    DWORD dwValue = 0, dwSize = 0;
    PWSTR wMultiSzValue = nullptr;
 
    auto cleanup = wil::scope_exit([&] {
        WIL_FreeMemory(wMultiSzValue);
                                   });

    dwResult = RegQueryValueEx(hKey, KeyName, nullptr, &dwType, nullptr, &dwSize);
    if (dwResult != ERROR_SUCCESS || dwType != REG_MULTI_SZ)
        return nullptr;

    wMultiSzValue = (PWSTR)WIL_AllocateMemory(dwSize + sizeof(WCHAR));
    if (wMultiSzValue == nullptr)
        return nullptr;

    dwResult = RegQueryValueEx(hKey, KeyName, nullptr, &dwType,
                               (PBYTE)wMultiSzValue, &dwSize);
    if (dwResult != ERROR_SUCCESS || dwType != REG_MULTI_SZ)
        return nullptr;

    wMultiSzValue[dwSize / sizeof(WCHAR)] = L'\0';

    PWSTR pwCurrentMultiSzValue;
    DWORD iValue;
    size_t cchCurrentValue, cValues;

    for (cValues = 0, pwCurrentMultiSzValue = wMultiSzValue;
         *pwCurrentMultiSzValue != L'\0';
         pwCurrentMultiSzValue += wcslen(pwCurrentMultiSzValue) + 1)
        cValues++;

    auto wszValues = (PWSTR *)WIL_AllocateMemory((cValues + 1) * sizeof(PWSTR));
    if (wszValues == nullptr)
        return nullptr;

    for (iValue = 0, pwCurrentMultiSzValue = wMultiSzValue, cchCurrentValue = wcslen(pwCurrentMultiSzValue) + 1;
         *pwCurrentMultiSzValue != L'\0';
         pwCurrentMultiSzValue += (cchCurrentValue = wcslen(pwCurrentMultiSzValue) + 1)) {
        size_t cbCurrentValue = cchCurrentValue * sizeof(WCHAR);

        wszValues[iValue] = (PWSTR)WIL_AllocateMemory(cbCurrentValue);
        if (wszValues[iValue] == nullptr)
            break; // FIXME

        memcpy(wszValues[iValue], pwCurrentMultiSzValue, cbCurrentValue);
        iValue++;
    }

    wszValues[iValue] = nullptr;

    return wszValues;
}
NTSTATUS
UnicodeToUTF8Alloc(_In_ PCWSTR wszUnicodeString,
                   _Out_ PCHAR *pszUTF8String)
{
    NTSTATUS Status;
    ULONG cbUTF8String = 0;
    SIZE_T cbUnicodeString = (wcslen(wszUnicodeString) + 1) * sizeof(WCHAR);
    ULONG ulcbUnicodeString = (ULONG)cbUnicodeString;

    *pszUTF8String = nullptr;

    if (cbUnicodeString < ulcbUnicodeString)
        RETURN_NTSTATUS(STATUS_INTEGER_OVERFLOW);

    Status = RtlUnicodeToUTF8N(nullptr, 0, &cbUTF8String, wszUnicodeString, ulcbUnicodeString);
    RETURN_IF_NTSTATUS_FAILED(Status);

    *pszUTF8String = (PCHAR)WIL_AllocateMemory(cbUTF8String);
    RETURN_NTSTATUS_IF_NULL_ALLOC(*pszUTF8String);

    Status = RtlUnicodeToUTF8N(*pszUTF8String, cbUTF8String, &cbUTF8String,
                               wszUnicodeString, ulcbUnicodeString);
    RETURN_IF_NTSTATUS_FAILED(Status);

    return STATUS_SUCCESS;
}

NTSTATUS
UTF8ToUnicodeAlloc(_In_ const PCHAR szUTF8String,
    _Out_ PWSTR* pwszUnicodeString)
{
    NTSTATUS Status;
    ULONG cbUnicodeString = 0;
    SIZE_T cbUTF8String = strlen(szUTF8String) + 1;
    ULONG ulcbUTF8String = (ULONG)cbUTF8String;

    *pwszUnicodeString = nullptr;

    if (cbUTF8String < ulcbUTF8String)
        RETURN_NTSTATUS(STATUS_INTEGER_OVERFLOW);

    Status = RtlUTF8ToUnicodeN(nullptr, 0, &cbUnicodeString, szUTF8String, ulcbUTF8String);
    RETURN_IF_NTSTATUS_FAILED(Status);

    *pwszUnicodeString = (PWSTR)WIL_AllocateMemory(cbUnicodeString);
    RETURN_NTSTATUS_IF_NULL_ALLOC(*pwszUnicodeString);

    Status = RtlUTF8ToUnicodeN(*pwszUnicodeString, cbUnicodeString, &cbUnicodeString,
                               szUTF8String, ulcbUTF8String);
    RETURN_IF_NTSTATUS_FAILED(Status);

    return STATUS_SUCCESS;
}
