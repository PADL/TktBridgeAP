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

NTSTATUS
DuplicateLsaString(IN PLSA_STRING Src, OUT PLSA_STRING *Dst)
{
    unique_lsa_string String;

    *Dst = NULL;

    String = (PLSA_STRING)LsaDispatchTable->AllocateLsaHeap(sizeof(*String));
    RETURN_NTSTATUS_IF_NULL_ALLOC(String);

    String->Buffer = (PCHAR)LsaDispatchTable->AllocateLsaHeap(Src->MaximumLength);
    RETURN_NTSTATUS_IF_NULL_ALLOC(String);

    RtlCopyMemory(String->Buffer, Src->Buffer, Src->MaximumLength);

    String->Length = Src->Length;
    String->MaximumLength = Src->MaximumLength;

    *Dst = String;

    return STATUS_SUCCESS;
}

DWORD
RegistryGetDWordValueForKey(HKEY hKey, PCWSTR KeyName)
{
    DWORD dwResult, dwType, dwValue, dwSize;

    dwType = REG_DWORD;
    dwValue = 0;
    dwSize = sizeof(dwValue);
    dwResult = RegQueryValueEx(hKey, KeyName, NULL, &dwType,
        (PBYTE)&dwValue, &dwSize);

    if (dwResult == ERROR_SUCCESS && dwType == REG_DWORD &&
        dwSize == sizeof(dwValue))
        return dwValue;

    return 0;
}

PWSTR
RegistryGetStringValueForKey(HKEY hKey, PCWSTR KeyName)
{
    DWORD dwResult, dwType, dwValue, dwSize;

    dwType = REG_SZ;
    dwValue = 0;
    dwSize = 0;
    dwResult = RegQueryValueEx(hKey, KeyName, NULL, &dwType, NULL, &dwSize);
    if (dwResult == ERROR_SUCCESS && dwType == REG_SZ) {
        LPWSTR szValue;

        szValue = (LPWSTR)LsaSpFunctionTable->AllocatePrivateHeap(dwSize + sizeof(WCHAR));
        if (szValue != NULL) {
            dwResult = RegQueryValueEx(hKey, KeyName, NULL, &dwType, NULL, &dwSize);
            if (dwResult == ERROR_SUCCESS && dwType == REG_SZ)
                szValue[dwSize / sizeof(WCHAR)] = 0;

            return szValue;
        }
    }

    return NULL;
}

VOID
RegistryFreeValue(PWSTR Value)
{
    if (Value)
	LsaSpFunctionTable->FreePrivateHeap(Value):
}
