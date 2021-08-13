/*
 * Copyright (C) 2021 PADL Software Pty Ltd.
 * All rights reserved.
 * Use is subject to license.
 *
 * CONFIDENTIAL
 *
 * AP initialization
 */

#include "TktBridgeAP.h"

PLSA_SECPKG_FUNCTION_TABLE LsaSpFunctionTable = NULL;

static SpGetInfoFn SpGetInfoTktBridgeAP;

SECPKG_PARAMETERS SpParameters;
ULONG APFlags = 0;
ULONG APLogLevel = 0;
LPWSTR APKdcHostName = NULL;
LPWSTR APRestrictPackage = NULL;

static NTSTATUS NTAPI
InitializePackage(
    IN ULONG AuthenticationPackageId,
    IN PLSA_DISPATCH_TABLE LsaDispatchTable,
    IN OPTIONAL PLSA_STRING Database,
    IN OPTIONAL PLSA_STRING Confidentiality,
    OUT PLSA_STRING *AuthenticationPackageName)
{
    return STATUS_INVALID_PARAMETER;
}

static NTSTATUS
InitializeHeimdalTracing(VOID)
{
    return STATUS_SUCCESS;
}

static VOID
RegistryNotifyChanged(VOID)
{
    DWORD dwResult;
    DWORD dwType, dwValue, dwSize;
    HKEY hKey;

    dwResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TKTBRIDGEAP_REGISTRY_KEY_W,
        0, KEY_QUERY_VALUE, &hKey);
    if (dwResult != ERROR_SUCCESS)
        return;

    dwType = REG_DWORD;
    dwValue = 0;
    dwSize = sizeof(dwValue);
    dwResult = RegQueryValueEx(hKey, L"Flags", NULL, &dwType,
        (PBYTE)&dwValue, &dwSize);
    if (dwResult == ERROR_SUCCESS &&
        dwType == REG_DWORD &&
        dwSize == sizeof(dwValue)) {
        APFlags &= ~(TKTBRIDGEAP_FLAG_USER);
        APFlags |= dwValue & TKTBRIDGEAP_FLAG_USER;
    }

    dwType = REG_DWORD;
    dwValue = 0;
    dwSize = sizeof(dwValue);
    dwResult = RegQueryValueEx(hKey, L"LogLevel", NULL, &dwType,
        (PBYTE)&dwValue, &dwSize);
    if (dwResult == ERROR_SUCCESS &&
        dwType == REG_DWORD &&
        dwSize == sizeof(dwValue)) {
        APLogLevel = dwValue;
    }

    dwType = REG_SZ;
    dwValue = 0;
    dwSize = 0;
    dwResult = RegQueryValueEx(hKey, L"KdcHostName", NULL, &dwType, NULL, &dwSize);
    if (dwResult == ERROR_SUCCESS && dwType == REG_SZ) {
        LPWSTR szValue;

        szValue = (LPWSTR)LsaSpFunctionTable->AllocatePrivateHeap(dwSize + sizeof(WCHAR));
        if (szValue != NULL) {
            dwResult = RegQueryValueEx(hKey, L"KdcHostName", NULL, &dwType, NULL, &dwSize);
            if (dwResult == ERROR_SUCCESS && dwType == REG_SZ)
                szValue[dwSize / sizeof(WCHAR)] = 0;

            LsaSpFunctionTable->FreePrivateHeap(APKdcHostName);
            APKdcHostName = szValue;
        }
    }

    dwType = REG_SZ;
    dwValue = 0;
    dwSize = 0;
    dwResult = RegQueryValueEx(hKey, L"RestrictPackage", NULL, &dwType, NULL, &dwSize);
    if (dwResult == ERROR_SUCCESS && dwType == REG_SZ) {
        LPWSTR szValue;

        szValue = (LPWSTR)LsaSpFunctionTable->AllocatePrivateHeap(dwSize + sizeof(WCHAR));
        if (szValue != NULL) {
            dwResult = RegQueryValueEx(hKey, L"RestrictPackage", NULL, &dwType, NULL, &dwSize);
            if (dwResult == ERROR_SUCCESS && dwType == REG_SZ)
                szValue[dwSize / sizeof(WCHAR)] = 0;

            LsaSpFunctionTable->FreePrivateHeap(APKdcHostName);
            APKdcHostName = szValue;
        }
    }
}

static NTSTATUS
InitializeRegistryNotification(VOID)
{
    auto watcher = wil::make_registry_watcher_nothrow(HKEY_LOCAL_MACHINE,
        TKTBRIDGEAP_REGISTRY_KEY_W, true, [&](wil::RegistryChangeKind) {
            ::RegistryNotifyChanged();
        });

    if (watcher == NULL)
        return STATUS_NO_MEMORY;

    return STATUS_SUCCESS;
}


static NTSTATUS NTAPI
SpInitialize(
    IN ULONG_PTR PackageId,
    IN PSECPKG_PARAMETERS Parameters,
    IN PLSA_SECPKG_FUNCTION_TABLE FunctionTable)
{
    NTSTATUS Status;

    _ASSERT(Parameters != NULL);
    _ASSERT(FunctionTable != NULL);

    RtlZeroMemory(&SpParameters, sizeof(SpParameters));

    SpParameters.Version = Parameters->Version;
    SpParameters.MachineState = Parameters->MachineState;
    SpParameters.SetupMode = Parameters->SetupMode;

    if (Parameters->DomainSid != NULL) {
        Status = RtlDuplicateSid(&SpParameters.DomainSid, Parameters->DomainSid);
        NT_RETURN_IF_NTSTATUS_FAILED(Status);
    }

    Status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
        &Parameters->DomainName,
        &SpParameters.DomainName);
    NT_RETURN_IF_NTSTATUS_FAILED(Status);

    Status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
        &Parameters->DnsDomainName,
        &SpParameters.DnsDomainName);
    NT_RETURN_IF_NTSTATUS_FAILED(Status);

    SpParameters.DomainGuid = Parameters->DomainGuid;

    InitializeHeimdalTracing();

    RegistryNotifyChanged();
    InitializeRegistryNotification();

    return Status;
}

static NTSTATUS NTAPI
SpShutdown(VOID)
{
    RtlFreeSid(SpParameters.DomainSid);
    RtlFreeUnicodeString(&SpParameters.DomainName);
    RtlFreeUnicodeString(&SpParameters.DnsDomainName);
    RtlZeroMemory(&SpParameters, sizeof(SpParameters));

    return STATUS_SUCCESS;
}

static SECPKG_FUNCTION_TABLE
TktBridgeAPFunctionTable = {
    .InitializePackage = InitializePackage,
    .Initialize = SpInitialize,
    .Shutdown = SpShutdown,
};

TKTBRIDGEAP_API NTSTATUS NTAPI
SpLsaModeInitialize(
    IN ULONG LsaVersion,
    OUT PULONG PackageVersion,
    OUT PSECPKG_FUNCTION_TABLE* ppTables,
    OUT PULONG pcTables)
{

    return STATUS_SUCCESS;
}