/*++

Copyright (c) PADL Software Pty Ltd, All rights reserved.

Module Name:

    logonpkg.cpp

Abstract:

    Ticket Bridge Authentciation Package (AP)

Environment:

    Local Security Authority (LSA)

--*/

#include "TktBridgeAP.h"

ULONG LsaAuthenticationPackageId = 0;
PLSA_DISPATCH_TABLE LsaDispatchTable = nullptr;
PLSA_SECPKG_FUNCTION_TABLE LsaSpFunctionTable = nullptr;

SECPKG_PARAMETERS SpParameters;
ULONG APFlags = 0;
ULONG APLogLevel = 0;
LPWSTR APKdcHostName = nullptr;
LPWSTR APRestrictPackage = nullptr;

extern "C" {
    static LSA_AP_INITIALIZE_PACKAGE InitializePackage;
    static SpInitializeFn SpInitialize;
    static SpShutdownFn SpShutdown;
    static SpGetInfoFn SpGetInfo;
}

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
    assert(DispatchTable != nullptr);

    LsaAuthenticationPackageId = AuthenticationPackageId;
    LsaDispatchTable = DispatchTable;
    *AuthenticationPackageName = nullptr;

    InitializeRegistryNotification();

    LSA_STRING APName;
    NTSTATUS Status;

    APName.Length = sizeof(TKTBRIDGEAP_PACKAGE_NAME_A) - 1;
    APName.MaximumLength = sizeof(TKTBRIDGEAP_PACKAGE_NAME_A);
    APName.Buffer = (PCHAR)TKTBRIDGEAP_PACKAGE_NAME_A;

    Status = DuplicateLsaString(&APName, AuthenticationPackageName);
    NT_RETURN_IF_NTSTATUS_FAILED(Status);

    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI
SpInitialize(
    IN ULONG_PTR PackageId,
    IN PSECPKG_PARAMETERS Parameters,
    IN PLSA_SECPKG_FUNCTION_TABLE FunctionTable)
{
    NTSTATUS Status;

    assert(Parameters != nullptr);
    assert(FunctionTable != nullptr);

    RtlZeroMemory(&SpParameters, sizeof(SpParameters));

    SpParameters.Version        = Parameters->Version;
    SpParameters.MachineState   = Parameters->MachineState;
    SpParameters.SetupMode      = Parameters->SetupMode;

    if (Parameters->DomainSid != nullptr) {
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

    if (APKdcHostName != nullptr) {
        WIL_FreeMemory(APKdcHostName);
        APKdcHostName = nullptr;
    }

    if (APRestrictPackage != nullptr) {
        WIL_FreeMemory(APRestrictPackage);
        APRestrictPackage = nullptr;
    }

    LsaAuthenticationPackageId = 0;
    LsaDispatchTable = nullptr;
    LsaSpFunctionTable = nullptr;

    EventUnregisterPADL_TktBridgeAP();

    return STATUS_SUCCESS;
}

static SECPKG_FUNCTION_TABLE
TktBridgeAPFunctionTable = {
    .InitializePackage = InitializePackage,
    .Initialize = SpInitialize,
    .Shutdown = SpShutdown,
    .GetInfo = SpGetInfo,
};

extern "C"
TKTBRIDGEAP_API NTSTATUS __cdecl
SpLsaModeInitialize(_In_ ULONG LsaVersion,
                    _Out_ PULONG PackageVersion,
                    _Out_ PSECPKG_FUNCTION_TABLE *ppTables,
                    _Out_ PULONG pcTables)
{
    if (LsaVersion != SECPKG_INTERFACE_VERSION) {
        DebugTrace(WINEVENT_LEVEL_ERROR,
            L"SpLsaModeInitialize: unsupported SPM interface version %08x", LsaVersion);
        RETURN_NTSTATUS(STATUS_INVALID_PARAMETER);
    }

    *PackageVersion = SECPKG_INTERFACE_VERSION_10;
    *ppTables = &TktBridgeAPFunctionTable;
    *pcTables = 1;

    DebugTrace(WINEVENT_LEVEL_VERBOSE,
        L"SpLsaModeInitialize: SPM version %08x", LsaVersion);

    EventRegisterPADL_TktBridgeAP();

    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI
SpGetInfo(OUT PSecPkgInfo PackageInfo)
{
    RtlZeroMemory(PackageInfo, sizeof(*PackageInfo));

    PackageInfo->fCapabilities  = SECPKG_FLAG_LOGON;
    PackageInfo->wVersion       = TKTBRIDGEAP_PACKAGE_VERSION;
    PackageInfo->wRPCID         = SECPKG_ID_NONE;
    PackageInfo->cbMaxToken     = 0;
    PackageInfo->Name           = (SEC_WCHAR *)TKTBRIDGEAP_PACKAGE_NAME_W;
    PackageInfo->Comment        = (SEC_WCHAR *)TKTBRIDGEAP_PACKAGE_COMMENT_W;

    return STATUS_SUCCESS;
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
    APFlags |= RegistryGetDWordValueForKey(hKey.get(), L"Flags") & TKTBRIDGEAP_FLAG_USER;

    APLogLevel = RegistryGetDWordValueForKey(hKey.get(), L"LogLevel");

    WIL_FreeMemory(APKdcHostName);
    APKdcHostName = RegistryGetStringValueForKey(hKey.get(), L"KdcHostName");

    WIL_FreeMemory(APRestrictPackage);
    APRestrictPackage = RegistryGetStringValueForKey(hKey.get(), L"RestrictPackage");

    return ERROR_SUCCESS;
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
