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

/* from LSA */
ULONG LsaAuthenticationPackageId = 0;
PLSA_DISPATCH_TABLE LsaDispatchTable = NULL;
PLSA_SECPKG_FUNCTION_TABLE LsaSpFunctionTable = NULL;

/* local state to be freed */
SECPKG_PARAMETERS SpParameters;
ULONG APFlags = 0;
ULONG APLogLevel = 0;
LPWSTR APKdcHostName = NULL;
LPWSTR APRestrictPackage = NULL;

static SpGetInfoFn SpGetInfo;

static NTSTATUS
InitializeRegistryNotification(VOID);

static NTSTATUS NTAPI
InitializePackage(
    IN ULONG AuthenticationPackageId,
    IN PLSA_DISPATCH_TABLE DispatchTable,
    IN OPTIONAL PLSA_STRING Database,
    IN OPTIONAL PLSA_STRING Confidentiality,
    OUT PLSA_STRING *AuthenticationPackageName)
{
    LsaAuthenticationPackageId = AuthenticationPackageId;
    LsaDispatchTable = DispatchTable;
    *AuthenticationPackageName = NULL;

    InitializeRegistryNotification();

    NTSTATUS Status;
    ULONG cbAPName = sizeof(TKTBRIDGEAP_PACKAGE_NAME_A);
    unique_lsa_string APName;

    APName = (PLSA_STRING)LsaDispatchTable->AllocateLsaHeap(sizeof(*APName));
    RETURN_NTSTATUS_IF_NULL_ALLOC(APName);

    APName->Buffer = (PCHAR)LsaDispatchTable->AllocateLsaHeap(cbAPName);
    RETURN_NTSTATUS_IF_NULL_ALLOC(APName->Buffer);

    RtlCopyMemory(APName->Buffer, TKTBRIDGEAP_PACKAGE_NAME_A, cbAPName);
    APName->Length = cbAPName - 1;
    APName->MaximumLength = cbAPName;
    *AuthenticationPackageName = APName;

    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI
SpInitialize(
    IN ULONG_PTR PackageId,
    IN PSECPKG_PARAMETERS Parameters,
    IN PLSA_SECPKG_FUNCTION_TABLE FunctionTable)
{
    NTSTATUS Status;

    static_assert(Parameters != NULL, "parameters must be non-NULL");
    static_assert(FunctionTable != NULL, "function table most be non-NULL");

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

    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI
SpShutdown(VOID)
{
    RtlFreeSid(SpParameters.DomainSid);
    RtlFreeUnicodeString(&SpParameters.DomainName);
    RtlFreeUnicodeString(&SpParameters.DnsDomainName);
    RtlZeroMemory(&SpParameters, sizeof(SpParameters));

    APFlags = 0;
    APLogLevel = 0;

    if (APKdcHostName) {
        LsaSpFunctionTable->FreePrivateHeap(APKdcHostName);
        APKdcHostName = NULL;
    }

    if (APRestrictPackage) {
        LsaSpFunctionTable->FreePrivateHeap(APRestrictPackage);
        APRestrictPackage = NULL;
    }

    LsaAuthenticationPackageId = 0;
    LsaDispatchTable = NULL;
    LsaSpFunctionTable = NULL;

    return STATUS_SUCCESS;
}

static SECPKG_FUNCTION_TABLE
TktBridgeAPFunctionTable = {
    .InitializePackage = InitializePackage,
    .Initialize = SpInitialize,
    .Shutdown = SpShutdown,
    .GetInfo = SpGetInfo,
};

TKTBRIDGEAP_API NTSTATUS NTAPI
SpLsaModeInitialize(
    IN ULONG LsaVersion,
    OUT PULONG PackageVersion,
    OUT PSECPKG_FUNCTION_TABLE *ppTables,
    OUT PULONG pcTables)
{
    if (LsaVersion != SECPKG_INTERFACE_VERSION) {
        DebugTrace(WINEVENT_LEVEL_ERROR,
            L"SpLsaModeInitialize: unsupported SPM interface version %08x", LsaVersion);
        return STATUS_INVALID_PARAMETER;
    }

    *PackageVersion = SECPKG_INTERFACE_VERSION_10;
    *ppTables = &TktBridgeAPFunctionTable;
    *pcTables = 1;

    DebugTrace(WINEVENT_LEVEL_VERBOSE,
        L"SpLsaModeInitialize: SPM version %08x", LsaVersion);

    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI
SpGetInfo(OUT PSecPkgInfo PackageInfo)
{
    RtlZeroMemory(PackageInfo, sizeof(*PackageInfo));

    PackageInfo->fCapabilities = SECPKG_FLAG_LOGON;
    PackageInfo->wVersion = TKTBRIDGEAP_PACKAGE_VERSION;
    PackageInfo->wRPCID = SECPKG_ID_NONE;
    PackageInfo->cbMaxToken = 0;
    PackageInfo->Name = (SEC_WCHAR *)TKTBRIDGEAP_PACKAGE_NAME_W;
    PackageInfo->Comment = (SEC_WCHAR *)TKTBRIDGEAP_PACKAGE_COMMENT_W;

    return STATUS_SUCCESS;
}


static DWORD
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

static PWSTR
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

static DWORD
RegistryNotifyChanged(VOID)
{
    DWORD dwResult;
    wil::unique_hkey hKey;

    dwResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TKTBRIDGEAP_REGISTRY_KEY_W,
        0, KEY_QUERY_VALUE, &hKey);
    RETURN_IF_WIN32_ERROR_EXPECTED(dwResult);

    APFlags &= ~(TKTBRIDGEAP_FLAG_USER);
    APFlags |= RegistryGetDWordValueForKey(hKey, L"Flags") & TKTBRIDGEAP_FLAG_USER;

    APLogLevel = RegistryGetDWordValueForKey(hKey, L"LogLevel");

    LsaSpFunctionTable->FreePrivateHeap(APKdcHostName);
    APKdcHostName = RegistryGetStringValueForKey(hKey, L"KdcHostName");

    LsaSpFunctionTable->FreePrivateHeap(APRestrictPackage);
    APRestrictPackage = RegistryGetStringValueForKey(hKey, L"RestrictPackage");
}

static NTSTATUS
InitializeRegistryNotification(VOID)
{
    RegistryNotifyChanged();

    auto watcher = wil::make_registry_watcher_nothrow(HKEY_LOCAL_MACHINE,
        TKTBRIDGEAP_REGISTRY_KEY_W, true, [&](wil::RegistryChangeKind) {
            ::RegistryNotifyChanged();
        });

    RETURN_NTSTATUS_IF_NULL_ALLOC(watcher);

    return STATUS_SUCCESS;
}
