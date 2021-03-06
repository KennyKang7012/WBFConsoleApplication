// WBFConsoleApplication.cpp : 此檔案包含 'main' 函式。程式會於該處開始執行及結束執行。
//

#include <iostream>
#include <string>
#include <tchar.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <conio.h>
#include <windows.h>
#include <winbio.h>
#include <winbio_types.h>
#include <winerror.h>
#include <wincred.h>
#include <locale.h>

#pragma comment(lib, "Winbio.lib")

using namespace std;

//------------------------------------------------------------------------
// Forward declarations.
HRESULT EnrollSysPoolWithCallback(
	BOOL bCancel,
	BOOL bDiscard,
	WINBIO_BIOMETRIC_SUBTYPE subFactor);

VOID CALLBACK EnrollCaptureCallback(
	__in_opt PVOID EnrollCallbackContext,
	__in HRESULT OperationStatus,
	__in WINBIO_REJECT_DETAIL RejectDetail);

typedef struct _ENROLL_CALLBACK_CONTEXT {
	WINBIO_SESSION_HANDLE SessionHandle;
	WINBIO_UNIT_ID UnitId;
	WINBIO_BIOMETRIC_SUBTYPE SubFactor;
} ENROLL_CALLBACK_CONTEXT, *PENROLL_CALLBACK_CONTEXT;

HRESULT CaptureSampleWithCallback(
	BOOL bCancel
);

VOID CALLBACK CaptureSampleCallback(
	__in_opt PVOID CaptureCallbackContext,
	__in HRESULT OperationStatus,
	__in WINBIO_UNIT_ID UnitId,
	__in_bcount(SampleSize) PWINBIO_BIR Sample,
	__in SIZE_T SampleSize,
	__in WINBIO_REJECT_DETAIL RejectDetail
);

HRESULT GetCredentialState();

HRESULT VerifyWithCallback(BOOL bCancel, WINBIO_BIOMETRIC_SUBTYPE subFactor);

VOID CALLBACK VerifyCallback(
	__in_opt PVOID VerifyCallbackContext,
	__in HRESULT OperationStatus,
	__in WINBIO_UNIT_ID UnitId,
	__in BOOLEAN Match,
	__in WINBIO_REJECT_DETAIL RejectDetail
);

HRESULT IdentifyWithCallback(BOOL bCancel);

VOID CALLBACK IdentifyCallback(
	__in_opt PVOID IdentifyCallbackContext,
	__in HRESULT OperationStatus,
	__in WINBIO_UNIT_ID UnitId,
	__in WINBIO_IDENTITY *Identity,
	__in WINBIO_BIOMETRIC_SUBTYPE SubFactor,
	__in WINBIO_REJECT_DETAIL RejectDetail
);

HRESULT LocateSensorWithCallback(BOOL bCancel);

VOID CALLBACK LocateSensorCallback(
	__in_opt PVOID LocateCallbackContext,
	__in HRESULT OperationStatus,
	__in WINBIO_UNIT_ID UnitId
);
//------------------------------------------------------------------------

typedef struct _SUBFACTOR_TEXT {
	WINBIO_BIOMETRIC_SUBTYPE SubFactor;
	LPCTSTR Text;
} SUBFACTOR_TEXT, *PSUBFACTOR_TEXT;

static const SUBFACTOR_TEXT g_SubFactorText[] = {
		{ WINBIO_SUBTYPE_NO_INFORMATION,             (L"(No information)") },
		{ WINBIO_ANSI_381_POS_RH_THUMB,              (L"RH thumb") },
		{ WINBIO_ANSI_381_POS_RH_INDEX_FINGER,       (L"RH index finger") },
		{ WINBIO_ANSI_381_POS_RH_MIDDLE_FINGER,      (L"RH middle finger") },
		{ WINBIO_ANSI_381_POS_RH_RING_FINGER,        (L"RH ring finger") },
		{ WINBIO_ANSI_381_POS_RH_LITTLE_FINGER,      (L"RH little finger") },
		{ WINBIO_ANSI_381_POS_LH_THUMB,              (L"LH thumb") },
		{ WINBIO_ANSI_381_POS_LH_INDEX_FINGER,       (L"LH index finger") },
		{ WINBIO_ANSI_381_POS_LH_MIDDLE_FINGER,      (L"LH middle finger") },
		{ WINBIO_ANSI_381_POS_LH_RING_FINGER,        (L"LH ring finger") },
		{ WINBIO_ANSI_381_POS_LH_LITTLE_FINGER,      (L"LH little finger") },
		{ WINBIO_SUBTYPE_ANY,                        (L"Any finger") },
};

static const SIZE_T k_SubFactorTextTableSize = sizeof(g_SubFactorText) / sizeof(SUBFACTOR_TEXT);

LPCTSTR ConvertSubFactorToString(__in WINBIO_BIOMETRIC_SUBTYPE SubFactor)
{
	SIZE_T index = 0;
	for (index = 0; index < k_SubFactorTextTableSize; ++index)
	{
		if (g_SubFactorText[index].SubFactor == SubFactor)
		{
			return g_SubFactorText[index].Text;
		}
	}
	return (L"<Unknown>");
}

typedef struct _REJECT_DETAIL_TEXT {
	WINBIO_REJECT_DETAIL RejectDetail;
	LPCTSTR Text;
} REJECT_DETAIL_TEXT, *PREJECT_DETAIL_TEXT;

static const REJECT_DETAIL_TEXT g_RejectDetailText[] = {
		{ WINBIO_FP_TOO_HIGH,        (L"Scan your fingerprint a little lower.") },
		{ WINBIO_FP_TOO_LOW,         (L"Scan your fingerprint a little higher.") },
		{ WINBIO_FP_TOO_LEFT,        (L"Scan your fingerprint more to the right.") },
		{ WINBIO_FP_TOO_RIGHT,       (L"Scan your fingerprint more to the left.") },
		{ WINBIO_FP_TOO_FAST,        (L"Scan your fingerprint more slowly.") },
		{ WINBIO_FP_TOO_SLOW,        (L"Scan your fingerprint more quickly.") },
		{ WINBIO_FP_POOR_QUALITY,    (L"The quality of the fingerprint scan was not sufficient to make a match.  Check to make sure the sensor is clean.") },
		{ WINBIO_FP_TOO_SKEWED,      (L"Hold your finger flat and straight when scanning your fingerprint.") },
		{ WINBIO_FP_TOO_SHORT,       (L"Use a longer stroke when scanning your fingerprint.") },
		{ WINBIO_FP_MERGE_FAILURE,   (L"Unable to merge samples into a single enrollment. Try to repeat the enrollment procedure from the beginning.") },
};

static const SIZE_T k_RejectDetailTextTableSize = sizeof(g_RejectDetailText) / sizeof(REJECT_DETAIL_TEXT);

LPCTSTR ConvertRejectDetailToString(__in WINBIO_REJECT_DETAIL RejectDetail)
{
	SIZE_T index = 0;
	for (index = 0; index < k_RejectDetailTextTableSize; ++index)
	{
		if (g_RejectDetailText[index].RejectDetail == RejectDetail)
		{
			return g_RejectDetailText[index].Text;
		}
	}
	return (L"Reason for failure couldn't be diagnosed.");
}

HRESULT EnumerateSensors()
{
	// Declare variables.
	HRESULT hr = S_OK;
	PWINBIO_UNIT_SCHEMA unitSchema = NULL;
	SIZE_T unitCount = 0;
	SIZE_T index = 0;

	// Enumerate the installed biometric units.
	hr = WinBioEnumBiometricUnits(
		WINBIO_TYPE_FINGERPRINT,        // Type of biometric unit
		&unitSchema,                    // Array of unit schemas
		&unitCount);                   // Count of unit schemas

	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioEnumBiometricUnits failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Display information for each installed biometric unit.
	wprintf_s(L"\nSensors: \n");
	for (index = 0; index < unitCount; ++index)
	{
		wprintf_s(L"\n[%lld]: \tUnit ID: %d\n",
			index,
			unitSchema[index].UnitId);
		wprintf_s(L"\tDevice instance ID: %s\n",
			unitSchema[index].DeviceInstanceId);
		wprintf_s(L"\tPool type: %d\n",
			unitSchema[index].PoolType);
		wprintf_s(L"\tBiometric factor: %d\n",
			unitSchema[index].BiometricFactor);
		wprintf_s(L"\tSensor subtype: %d\n",
			unitSchema[index].SensorSubType);
		wprintf_s(L"\tSensor capabilities: 0x%08x\n",
			unitSchema[index].Capabilities);
		wprintf_s(L"\tDescription: %s\n",
			unitSchema[index].Description);
		wprintf_s(L"\tManufacturer: %s\n",
			unitSchema[index].Manufacturer);
		wprintf_s(L"\tModel: %S\n",
			unitSchema[index].Model);
		wprintf_s(L"\tSerial no: %s\n",
			unitSchema[index].SerialNumber);
		wprintf_s(L"\tFirmware version: [%d.%d]\n",
			unitSchema[index].FirmwareVersion.MajorVersion,
			unitSchema[index].FirmwareVersion.MinorVersion);
	}


e_Exit:
	if (unitSchema != NULL)
	{
		WinBioFree(unitSchema);
		unitSchema = NULL;
	}

	//wprintf_s(L"\nPress any key to exit...");
	//_getch();
	return hr;
}

HRESULT LocateSensor()
{
	HRESULT hr = S_OK;
	WINBIO_SESSION_HANDLE sessionHandle = NULL;
	WINBIO_UNIT_ID unitId = 0;

	// Connect to the system pool. 
	hr = WinBioOpenSession(
		WINBIO_TYPE_FINGERPRINT,    // Service provider
		WINBIO_POOL_SYSTEM,         // Pool type
		WINBIO_FLAG_DEFAULT,        // Configuration and access
		NULL,                       // Array of biometric unit IDs
		0,                          // Count of biometric unit IDs
		NULL,                       // Database ID
		&sessionHandle              // [out] Session handle
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioEnumBiometricUnits failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Locate the sensor.
	wprintf_s(L"\n Tap the sensor once...\n");
	hr = WinBioLocateSensor(sessionHandle, &unitId);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioLocateSensor failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}
	wprintf_s(L"\n Sensor located successfully. ");
	wprintf_s(L"\n Unit ID = %d \n", unitId);

e_Exit:
	if (sessionHandle != NULL)
	{
		WinBioCloseSession(sessionHandle);
		sessionHandle = NULL;
	}

	wprintf_s(L"\n Hit any key to exit...");
	_getch();
	return hr;
}

//------------------------------------------------------------------------
// The following function retrieves the identity of the current user.
// This is a helper function and is not part of the Windows Biometric
// Framework API.
//
HRESULT GetCurrentUserIdentity(__inout PWINBIO_IDENTITY Identity)
{
	// Declare variables.
	HRESULT hr = S_OK;
	HANDLE tokenHandle = NULL;
	DWORD bytesReturned = 0;
	struct {
		TOKEN_USER tokenUser;
		BYTE buffer[SECURITY_MAX_SID_SIZE];
	} tokenInfoBuffer;

	// Zero the input identity and specify the type.
	ZeroMemory(Identity, sizeof(WINBIO_IDENTITY));
	Identity->Type = WINBIO_ID_TYPE_NULL;

	// Open the access token associated with the
	// current process
	if (!OpenProcessToken(
		GetCurrentProcess(),            // Process handle
		TOKEN_READ,                     // Read access only
		&tokenHandle))                  // Access token handle
	{
		DWORD win32Status = GetLastError();
		wprintf_s(L"Cannot open token handle: %d\n", win32Status);
		hr = HRESULT_FROM_WIN32(win32Status);
		goto e_Exit;
	}

	// Zero the tokenInfoBuffer structure.
	ZeroMemory(&tokenInfoBuffer, sizeof(tokenInfoBuffer));

	// Retrieve information about the access token. In this case,
	// retrieve a SID.
	if (!GetTokenInformation(
		tokenHandle,                    // Access token handle
		TokenUser,                      // User for the token
		&tokenInfoBuffer.tokenUser,     // Buffer to fill
		sizeof(tokenInfoBuffer),        // Size of the buffer
		&bytesReturned))                // Size needed
	{
		DWORD win32Status = GetLastError();
		wprintf_s(L"Cannot query token information: %d\n", win32Status);
		hr = HRESULT_FROM_WIN32(win32Status);
		goto e_Exit;
	}

	// Copy the SID from the tokenInfoBuffer structure to the
	// WINBIO_IDENTITY structure. 
	CopySid(
		SECURITY_MAX_SID_SIZE,
		Identity->Value.AccountSid.Data,
		tokenInfoBuffer.tokenUser.User.Sid
	);

	// Specify the size of the SID and assign WINBIO_ID_TYPE_SID
	// to the type member of the WINBIO_IDENTITY structure.
	Identity->Value.AccountSid.Size = GetLengthSid(tokenInfoBuffer.tokenUser.User.Sid);
	Identity->Type = WINBIO_ID_TYPE_SID;

e_Exit:

	if (tokenHandle != NULL)
	{
		CloseHandle(tokenHandle);
	}
	return hr;
}

HRESULT RemoveCredential()
{
	HRESULT hr = S_OK;
	WINBIO_IDENTITY identity = { 0 };

	// Find the identity of the user.
	wprintf_s(L"\n Finding user identity.\n");
	hr = GetCurrentUserIdentity(&identity);
	if (FAILED(hr))
	{
		wprintf(L"\n User identity not found. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Remove the user credentials.
	hr = WinBioRemoveCredential(identity, WINBIO_CREDENTIAL_PASSWORD);
	if (FAILED(hr))
	{
		wprintf(L"\n WinBioRemoveCredential failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	wprintf_s(L"\n User credentials successfully removed.\n");

e_Exit:

	//wprintf_s(L"\n Press any key to exit...");
	//_getch();
	return hr;
}

#if 0
//------------------------------------------------------------------------
// The following function displays a dialog box to prompt a user
// for credentials.
//
HRESULT GetCredentials(PSID pSid, PVOID* ppvAuthBlob, ULONG* pcbAuthBlob)
{
	HRESULT hr = S_OK;
	DWORD   dwResult;
	WCHAR   szUsername[MAX_PATH] = { 0 };
	DWORD   cchUsername = ARRAYSIZE(szUsername);
	WCHAR   szPassword[MAX_PATH] = { 0 };
	WCHAR   szDomain[MAX_PATH] = { 0 };
	DWORD   cchDomain = ARRAYSIZE(szDomain);
	WCHAR   szDomainAndUser[MAX_PATH] = { 0 };
	DWORD   cchDomainAndUser = ARRAYSIZE(szDomainAndUser);
	PVOID   pvInAuthBlob = NULL;
	ULONG   cbInAuthBlob = 0;
	PVOID   pvAuthBlob = NULL;
	ULONG   cbAuthBlob = 0;
	CREDUI_INFOW ui;
	ULONG   ulAuthPackage = 0;
	BOOL    fSave = FALSE;

	static const WCHAR WINBIO_CREDPROV_TEST_PASSWORD_PROMPT_MESSAGE[] =
		L"Enter your current password to enable biometric logon.";

	static const WCHAR WINBIO_CREDPROV_TEST_PASSWORD_PROMPT_CAPTION[] =
		L"Biometric Log On Enrollment";

	if (NULL == pSid || NULL == ppvAuthBlob || NULL == pcbAuthBlob)
	{
		return E_INVALIDARG;
	}

	// Retrieve the user name and domain name.
	SID_NAME_USE    SidUse;
	DWORD           cchTmpUsername = cchUsername;
	DWORD           cchTmpDomain = cchDomain;

	if (!LookupAccountSidW(
		NULL,             // Local computer
		pSid,             // Security identifier for user
		szUsername,       // User name
		&cchTmpUsername,  // Size of user name
		szDomain,         // Domain name
		&cchTmpDomain,    // Size of domain name
		&SidUse))         // Account type
	{
		dwResult = GetLastError();
		hr = HRESULT_FROM_WIN32(dwResult);
		wprintf_s(L"\n LookupAccountSidLocalW failed: hr = 0x%x\n", hr);
		return hr;
	}

	// Combine the domain and user names.
	swprintf_s(
		szDomainAndUser,
		cchDomainAndUser,
		L"%s\\%s",
		szDomain,
		szUsername);

	// Call CredPackAuthenticationBufferW once to determine the size,
	// in bytes, of the authentication buffer.
	if (!CredPackAuthenticationBufferW(
		0,                // Reserved
		szDomainAndUser,  // Domain\User name
		szPassword,       // User Password
		NULL,             // Packed credentials
		&cbInAuthBlob)    // Size, in bytes, of credentials
		&& GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		dwResult = GetLastError();
		hr = HRESULT_FROM_WIN32(dwResult);
		wprintf_s(L"\n CredPackAuthenticationBufferW (1) failed: ");
		wprintf_s(L"hr = 0x%x\n", hr);
	}

	// Allocate memory for the input buffer.
	pvInAuthBlob = CoTaskMemAlloc(cbInAuthBlob);
	if (!pvInAuthBlob)
	{
		cbInAuthBlob = 0;
		wprintf_s(L"\n CoTaskMemAlloc() Out of memory.\n");
		return HRESULT_FROM_WIN32(ERROR_OUTOFMEMORY);
	}

	// Call CredPackAuthenticationBufferW again to retrieve the
	// authentication buffer.
	if (!CredPackAuthenticationBufferW(
		0,
		szDomainAndUser,
		szPassword,
		(PBYTE)pvInAuthBlob,
		&cbInAuthBlob))
	{
		dwResult = GetLastError();
		hr = HRESULT_FROM_WIN32(dwResult);
		wprintf_s(L"\n CredPackAuthenticationBufferW (2) failed: ");
		wprintf_s(L"hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Display a dialog box to request credentials.
	ui.cbSize = sizeof(ui);
	ui.hwndParent = GetConsoleWindow();
	ui.pszMessageText = WINBIO_CREDPROV_TEST_PASSWORD_PROMPT_MESSAGE;
	ui.pszCaptionText = WINBIO_CREDPROV_TEST_PASSWORD_PROMPT_CAPTION;
	ui.hbmBanner = NULL;

	dwResult = CredUIPromptForWindowsCredentialsW(
		&ui,             // Customizing information
		0,               // Error code to display
		&ulAuthPackage,  // Authorization package
		pvInAuthBlob,    // Credential byte array
		cbInAuthBlob,    // Size of credential input buffer
		&pvAuthBlob,     // Output credential byte array
		&cbAuthBlob,     // Size of credential byte array
		&fSave,          // Select the save check box.
		CREDUIWIN_IN_CRED_ONLY |
		CREDUIWIN_ENUMERATE_CURRENT_USER
	);
	if (dwResult != NO_ERROR)
	{
		hr = HRESULT_FROM_WIN32(dwResult);
		wprintf_s(L"\n CredUIPromptForWindowsCredentials failed: ");
		wprintf_s(L"0x%08x\n", dwResult);
		goto e_Exit;
	}

	*ppvAuthBlob = pvAuthBlob;
	*pcbAuthBlob = cbAuthBlob;

e_Exit:
	// Delete the input authentication byte array.
	if (pvInAuthBlob)
	{
		SecureZeroMemory(pvInAuthBlob, cbInAuthBlob);
		CoTaskMemFree(pvInAuthBlob);
		pvInAuthBlob = NULL;
	};
	return hr;
}

HRESULT SetCredential()
{
	// Declare variables.
	HRESULT hr = S_OK;
	ULONG   ulAuthPackage = 0;
	PVOID   pvAuthBlob = NULL;
	ULONG   cbAuthBlob = 0;
	WINBIO_IDENTITY identity;
	PSID pSid = NULL;

	// Find the identity of the user.
	wprintf_s(L"\n Finding user identity.\n");
	hr = GetCurrentUserIdentity(&identity);
	if (FAILED(hr))
	{
		wprintf_s(L"\n User identity not found. hr = 0x%x\n", hr);
		return hr;
	}

	// Set a pointer to the security descriptor for the user.
	pSid = identity.Value.AccountSid.Data;

	// Retrieve a byte array that contains credential information.
	hr = GetCredentials(pSid, &pvAuthBlob, &cbAuthBlob);
	if (FAILED(hr))
	{
		wprintf_s(L"\n GetCredentials failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Set the credentials.
	hr = WinBioSetCredential(
		WINBIO_CREDENTIAL_PASSWORD,     // Type of credential.
		(PUCHAR)pvAuthBlob,             // Credentials byte array
		cbAuthBlob,                     // Size of credentials
		WINBIO_PASSWORD_PACKED);        // Credentials format

	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioSetCredential failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}
	wprintf_s(L"\n Credentials successfully set.\n");

e_Exit:
	// Delete the authentication byte array.
	if (NULL != pvAuthBlob)
	{
		SecureZeroMemory(pvAuthBlob, cbAuthBlob);
		CoTaskMemFree(pvAuthBlob);
		pvAuthBlob = NULL;
	}

	wprintf_s(L"\n Press any key to exit...");
	_getch();
	return hr;
}
#endif

HRESULT Verify(WINBIO_BIOMETRIC_SUBTYPE subFactor)
{
	HRESULT hr = S_OK;
	WINBIO_SESSION_HANDLE sessionHandle = NULL;
	WINBIO_UNIT_ID unitId = 0;
	WINBIO_REJECT_DETAIL rejectDetail = 0;
	WINBIO_IDENTITY identity = { 0 };
	BOOLEAN match = FALSE;

	// Find the identity of the user.
	hr = GetCurrentUserIdentity(&identity);
	if (FAILED(hr))
	{
		wprintf_s(L"\n User identity not found. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Connect to the system pool. 
	hr = WinBioOpenSession(
		WINBIO_TYPE_FINGERPRINT,    // Service provider
		WINBIO_POOL_SYSTEM,         // Pool type
		WINBIO_FLAG_DEFAULT,        // Configuration and access
		NULL,                       // Array of biometric unit IDs
		0,                          // Count of biometric unit IDs
		NULL,                       // Database ID
		&sessionHandle              // [out] Session handle
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioOpenSession failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Verify a biometric sample.
	wprintf_s(L"\n Calling WinBioVerify - Swipe finger on sensor...\n");
	hr = WinBioVerify(
		sessionHandle,
		&identity,
		subFactor,
		&unitId,
		&match,
		&rejectDetail
	);
	wprintf_s(L"\n Swipe processed - Unit ID: %d\n", unitId);
	if (FAILED(hr))
	{
		if (hr == WINBIO_E_NO_MATCH)
		{
			wprintf_s(L"\n- NO MATCH - identity verification failed.\n");
		}
		else if (hr == WINBIO_E_BAD_CAPTURE)
		{
			wprintf_s(L"\n- Bad capture; reason: %d. (%s)\n", rejectDetail, ConvertRejectDetailToString(rejectDetail));
		}
		else
		{
			wprintf_s(L"\n WinBioVerify failed. hr = 0x%x\n", hr);
		}
		goto e_Exit;
	}
	wprintf_s(L"\n Fingerprint verified: %d\n", match);


e_Exit:
	if (sessionHandle != NULL)
	{
		WinBioCloseSession(sessionHandle);
		sessionHandle = NULL;
	}
	wprintf_s(L"\n Press any key to exit...");
	_getch();
	return hr;
}

HRESULT EnumEnrollments()
{
	// Declare variables.
	HRESULT hr = S_OK;
	WINBIO_IDENTITY identity = { 0 };
	WINBIO_SESSION_HANDLE sessionHandle = NULL;
	WINBIO_UNIT_ID unitId = 0;
	PWINBIO_BIOMETRIC_SUBTYPE subFactorArray = NULL;
	WINBIO_BIOMETRIC_SUBTYPE SubFactor = 0;
	SIZE_T subFactorCount = 0;
	WINBIO_REJECT_DETAIL rejectDetail = 0;
	WINBIO_BIOMETRIC_SUBTYPE subFactor = WINBIO_SUBTYPE_NO_INFORMATION;

	// Connect to the system pool. 
	hr = WinBioOpenSession(
		WINBIO_TYPE_FINGERPRINT,    // Service provider
		WINBIO_POOL_SYSTEM,         // Pool type
		WINBIO_FLAG_DEFAULT,        // Configuration and access
		NULL,                       // Array of biometric unit IDs
		0,                          // Count of biometric unit IDs
		NULL,                       // Database ID
		&sessionHandle              // [out] Session handle
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioOpenSession failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Locate the biometric sensor and retrieve a WINBIO_IDENTITY object.
	wprintf_s(L"\n Calling WinBioIdentify - Swipe finger on sensor...\n");
	hr = WinBioIdentify(
		sessionHandle,              // Session handle
		&unitId,                    // Biometric unit ID
		&identity,                  // User SID
		&subFactor,                 // Finger sub factor
		&rejectDetail               // Rejection information
	);
	wprintf_s(L"\n Swipe processed - Unit ID: %d\n", unitId);
	if (FAILED(hr))
	{
		if (hr == WINBIO_E_UNKNOWN_ID)
		{
			wprintf_s(L"\n Unknown identity.\n");
		}
		else if (hr == WINBIO_E_BAD_CAPTURE)
		{
			wprintf_s(L"\n Bad capture; reason: %d. (%s)\n", rejectDetail, ConvertRejectDetailToString(rejectDetail));
		}
		else
		{
			wprintf_s(L"\n WinBioEnumBiometricUnits failed. hr = 0x%x\n", hr);
		}
		goto e_Exit;
	}
	else
	{
		wprintf_s(L"Biometric unit ID = 0x%x\n", unitId);
		//wprintf_s(L"User SID = %08x-%04x-%04x-%08x\n", identity.Value.TemplateGuid.Data1, identity.Value.TemplateGuid.Data2, identity.Value.TemplateGuid.Data3, identity.Value.TemplateGuid.Data4);
		wprintf_s(L"User SID = %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X\n", 
			identity.Value.TemplateGuid.Data1,
			identity.Value.TemplateGuid.Data2,
			identity.Value.TemplateGuid.Data3,
			identity.Value.TemplateGuid.Data4[0],
			identity.Value.TemplateGuid.Data4[1],
			identity.Value.TemplateGuid.Data4[2],
			identity.Value.TemplateGuid.Data4[3],
			identity.Value.TemplateGuid.Data4[4],
			identity.Value.TemplateGuid.Data4[5],
			identity.Value.TemplateGuid.Data4[6],
			identity.Value.TemplateGuid.Data4[7]);
		wprintf_s(L"Finger sub factor = 0x%x. (%s)\n", subFactor, ConvertSubFactorToString(subFactor));
	}

	// Retrieve the biometric sub-factors for the template.
	hr = WinBioEnumEnrollments(
		sessionHandle,              // Session handle
		unitId,                     // Biometric unit ID
		&identity,                  // Template ID
		&subFactorArray,            // Subfactors
		&subFactorCount             // Count of subfactors
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioEnumEnrollments failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Print the sub-factor(s) to the console.
	wprintf_s(L"\n Enrollments for this user on Unit ID %d:", unitId);
	wprintf_s(L"\n Enrollments subFactorCount %lld:", subFactorCount);
	for (SIZE_T index = 0; index < subFactorCount; ++index)
	{
		SubFactor = subFactorArray[index];
		switch (SubFactor)
		{
			case WINBIO_ANSI_381_POS_RH_THUMB:
				wprintf_s(L"\n   RH thumb\n");
				break;
			case WINBIO_ANSI_381_POS_RH_INDEX_FINGER:
				wprintf_s(L"\n   RH index finger\n");
				break;
			case WINBIO_ANSI_381_POS_RH_MIDDLE_FINGER:
				wprintf_s(L"\n   RH middle finger\n");
				break;
			case WINBIO_ANSI_381_POS_RH_RING_FINGER:
				wprintf_s(L"\n   RH ring finger\n");
				break;
			case WINBIO_ANSI_381_POS_RH_LITTLE_FINGER:
				wprintf_s(L"\n   RH little finger\n");
				break;
			case WINBIO_ANSI_381_POS_LH_THUMB:
				wprintf_s(L"\n   LH thumb\n");
				break;
			case WINBIO_ANSI_381_POS_LH_INDEX_FINGER:
				wprintf_s(L"\n   LH index finger\n");
				break;
			case WINBIO_ANSI_381_POS_LH_MIDDLE_FINGER:
				wprintf_s(L"\n   LH middle finger\n");
				break;
			case WINBIO_ANSI_381_POS_LH_RING_FINGER:
				wprintf_s(L"\n   LH ring finger\n");
				break;
			case WINBIO_ANSI_381_POS_LH_LITTLE_FINGER:
				wprintf_s(L"\n   LH little finger\n");
				break;
			default:
				wprintf_s(L"\n   The sub-factor is not correct\n");
				break;
		}
	}

e_Exit:
	if (subFactorArray != NULL)
	{
		WinBioFree(subFactorArray);
		subFactorArray = NULL;
	}

	if (sessionHandle != NULL)
	{
		WinBioCloseSession(sessionHandle);
		sessionHandle = NULL;
	}

	wprintf_s(L"\n Press any key to exit...");
	_getch();
	return hr;
}

HRESULT EnrollSysPool(BOOL discardEnrollment, WINBIO_BIOMETRIC_SUBTYPE subFactor)
{
	HRESULT hr = S_OK;
	WINBIO_IDENTITY identity = { 0 };
	WINBIO_SESSION_HANDLE sessionHandle = NULL;
	WINBIO_UNIT_ID unitId = 0;
	WINBIO_REJECT_DETAIL rejectDetail = 0;
	BOOLEAN isNewTemplate = TRUE;

	// Connect to the system pool. 
	hr = WinBioOpenSession(
		WINBIO_TYPE_FINGERPRINT,    // Service provider
		WINBIO_POOL_SYSTEM,         // Pool type
		WINBIO_FLAG_DEFAULT,        // Configuration and access
		NULL,                       // Array of biometric unit IDs
		0,                          // Count of biometric unit IDs
		NULL,                       // Database ID
		&sessionHandle              // [out] Session handle
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioOpenSession failed. ");
		wprintf_s(L"hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Locate a sensor.
	wprintf_s(L"\n Swipe your finger on the sensor...\n");
	hr = WinBioLocateSensor(sessionHandle, &unitId);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioLocateSensor failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Begin the enrollment sequence. 
	wprintf_s(L"\n Starting enrollment sequence...\n");
	hr = WinBioEnrollBegin(
		sessionHandle,      // Handle to open biometric session
		subFactor,          // Finger to create template for
		unitId              // Biometric unit ID
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioEnrollBegin failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Capture enrollment information by swiping the sensor with
	// the finger identified by the subFactor argument in the 
	// WinBioEnrollBegin function.
	for (int swipeCount = 1;; ++swipeCount)
	{
		wprintf_s(L"\n Swipe the sensor to capture %s sample.",
			(swipeCount == 1) ? L"the first" : L"another");

		hr = WinBioEnrollCapture(
			sessionHandle,  // Handle to open biometric session
			&rejectDetail   // [out] Failure information
		);

		wprintf_s(L"\n Sample %d captured from unit number %d.",
			swipeCount,
			unitId);

		if (hr == WINBIO_I_MORE_DATA)
		{
			wprintf_s(L"\n    More data required.\n");
			continue;
		}
		if (FAILED(hr))
		{
			if (hr == WINBIO_E_BAD_CAPTURE)
			{
				wprintf_s(L"\n  Error: Bad capture; reason: %d. (%s)",
					rejectDetail, ConvertRejectDetailToString(rejectDetail));
				continue;
			}
			else
			{
				wprintf_s(L"\n WinBioEnrollCapture failed. hr = 0x%x", hr);
				goto e_Exit;
			}
		}
		else
		{
			wprintf_s(L"\n    Template completed.\n");
			break;
		}
	}

	// Discard the enrollment if the appropriate flag is set.
	// Commit the enrollment if it is not discarded.
	if (discardEnrollment == TRUE)
	{
		wprintf_s(L"\n Discarding enrollment...\n\n");
		hr = WinBioEnrollDiscard(sessionHandle);
		if (FAILED(hr))
		{
			wprintf_s(L"\n WinBioLocateSensor failed. hr = 0x%x\n", hr);
		}
		goto e_Exit;
	}
	else
	{
		wprintf_s(L"\n Committing enrollment...\n");
		hr = WinBioEnrollCommit(
			sessionHandle,      // Handle to open biometric session
			&identity,          // WINBIO_IDENTITY object for the user
			&isNewTemplate);    // Is this a new template

		if (FAILED(hr))
		{
			wprintf_s(L"\n WinBioEnrollCommit failed. hr = 0x%x\n", hr);
			goto e_Exit;
		}
	}

e_Exit:
	if (sessionHandle != NULL)
	{
		WinBioCloseSession(sessionHandle);
		sessionHandle = NULL;
	}

	wprintf_s(L" Press any key to continue...");
	_getch();
	return hr;
}

HRESULT Identify()
{
	// Declare variables.
	HRESULT hr = S_OK;
	WINBIO_IDENTITY identity = { 0 };
	WINBIO_SESSION_HANDLE sessionHandle = NULL;
	WINBIO_UNIT_ID unitId = 0;
	PWINBIO_BIOMETRIC_SUBTYPE subFactorArray = NULL;
	WINBIO_BIOMETRIC_SUBTYPE SubFactor = 0;
	SIZE_T subFactorCount = 0;
	WINBIO_REJECT_DETAIL rejectDetail = 0;
	WINBIO_BIOMETRIC_SUBTYPE subFactor = WINBIO_SUBTYPE_NO_INFORMATION;


	// Connect to the system pool. 
	hr = WinBioOpenSession(
		WINBIO_TYPE_FINGERPRINT,    // Service provider
		WINBIO_POOL_SYSTEM,         // Pool type
		WINBIO_FLAG_DEFAULT,        // Configuration and access
		NULL,                       // Array of biometric unit IDs
		0,                          // Count of biometric unit IDs
		NULL,                       // Database ID
		&sessionHandle              // [out] Session handle
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioOpenSession failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Locate the biometric sensor and retrieve a WINBIO_IDENTITY object.
	wprintf_s(L"\n Calling WinBioIdentify - Swipe finger on sensor...\n");
	hr = WinBioIdentify(
		sessionHandle,              // Session handle
		&unitId,                    // Biometric unit ID
		&identity,                  // User SID
		&subFactor,                 // Finger sub factor
		&rejectDetail               // Rejection information
	);
	wprintf_s(L"\n Swipe processed - Unit ID: %d\n", unitId);
	if (FAILED(hr))
	{
		if (hr == WINBIO_E_UNKNOWN_ID)
		{
			wprintf_s(L"\n Unknown identity.\n");
		}
		else if (hr == WINBIO_E_BAD_CAPTURE)
		{
			wprintf_s(L"\n Bad capture; reason: %d. (%s)\n", rejectDetail, ConvertRejectDetailToString(rejectDetail));
		}
		else
		{
			wprintf_s(L"\n WinBioEnumBiometricUnits failed. hr = 0x%x\n", hr);
		}
		goto e_Exit;
	}
	else
	{
		wprintf_s(L"\n subFactor = %d. (%s)\n", subFactor, ConvertSubFactorToString(subFactor));
	}


e_Exit:
	if (subFactorArray != NULL)
	{
		WinBioFree(subFactorArray);
		subFactorArray = NULL;
	}

	if (sessionHandle != NULL)
	{
		WinBioCloseSession(sessionHandle);
		sessionHandle = NULL;
	}

	wprintf_s(L"\n Press any key to exit...");
	_getch();
	return hr;
}

HRESULT CaptureSample()
{
	HRESULT hr = S_OK;
	WINBIO_SESSION_HANDLE sessionHandle = NULL;
	WINBIO_UNIT_ID unitId = 0;
	WINBIO_REJECT_DETAIL rejectDetail = 0;
	PWINBIO_BIR sample = NULL;
	SIZE_T sampleSize = 0;

	// Connect to the system pool. 
	hr = WinBioOpenSession(
		WINBIO_TYPE_FINGERPRINT,    // Service provider
		WINBIO_POOL_SYSTEM,         // Pool type
		WINBIO_FLAG_RAW,            // Access: Capture raw data
		NULL,                       // Array of biometric unit IDs
		0,                          // Count of biometric unit IDs
		WINBIO_DB_DEFAULT,          // Default database
		&sessionHandle              // [out] Session handle
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioOpenSession failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Capture a biometric sample.
	wprintf_s(L"\n Calling WinBioCaptureSample - Swipe sensor...\n");
	hr = WinBioCaptureSample(
		sessionHandle,
		WINBIO_NO_PURPOSE_AVAILABLE,
		WINBIO_DATA_FLAG_RAW,
		&unitId,
		&sample,
		&sampleSize,
		&rejectDetail
	);
	if (FAILED(hr))
	{
		if (hr == WINBIO_E_BAD_CAPTURE)
		{
			wprintf_s(L"\n Bad capture; reason: %d. (%s)\n", rejectDetail, ConvertRejectDetailToString(rejectDetail));
		}
		else
		{
			wprintf_s(L"\n WinBioCaptureSample failed. hr = 0x%x\n", hr);
		}
		goto e_Exit;
	}

	wprintf_s(L"\n Swipe processed - Unit ID: %d\n", unitId);
	wprintf_s(L"\n Captured %lld bytes.\n", sampleSize);

e_Exit:
	if (sample != NULL)
	{
		WinBioFree(sample);
		sample = NULL;
	}

	if (sessionHandle != NULL)
	{
		WinBioCloseSession(sessionHandle);
		sessionHandle = NULL;
	}

	wprintf_s(L"\n Press any key to exit...");
	_getch();
	return hr;
}

//------------------------------------------------------------------------
// The following function displays a GUID to the console window.
//
VOID DisplayGuid(__in PWINBIO_UUID Guid)
{
	wprintf_s(
		L"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		Guid->Data1,
		Guid->Data2,
		Guid->Data3,
		Guid->Data4[0],
		Guid->Data4[1],
		Guid->Data4[2],
		Guid->Data4[3],
		Guid->Data4[4],
		Guid->Data4[5],
		Guid->Data4[6],
		Guid->Data4[7]
	);
}

HRESULT EnumDatabases()
{
	// Declare variables.
	HRESULT hr = S_OK;
	PWINBIO_STORAGE_SCHEMA storageSchemaArray = NULL;
	SIZE_T storageCount = 0;
	SIZE_T index = 0;

	// Enumerate the databases.
	hr = WinBioEnumDatabases(
		WINBIO_TYPE_FINGERPRINT,    // Type of biometric unit
		&storageSchemaArray,        // Array of database schemas
		&storageCount);            // Number of database schemas
	if (FAILED(hr))
	{
		wprintf_s(L"\nWinBioEnumDatabases failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Display information for each database.
	wprintf_s(L"\nDatabases:\n");
	for (index = 0; index < storageCount; ++index)
	{
		wprintf_s(L"\n[%lld]: \tBiometric factor: 0x%08x\n",
			index,
			storageSchemaArray[index].BiometricFactor);

		wprintf_s(L"\tDatabase ID: ");
		DisplayGuid(&storageSchemaArray[index].DatabaseId);
		wprintf_s(L"\n");

		wprintf_s(L"\tData format: ");
		DisplayGuid(&storageSchemaArray[index].DataFormat);
		wprintf_s(L"\n");

		wprintf_s(L"\tAttributes:  0x%08x\n",
			storageSchemaArray[index].Attributes);

		wprintf_s(L"\tFile path:   %ws\n",
			storageSchemaArray[index].FilePath);

		wprintf_s(L"\tCnx string:  %ws\n",
			storageSchemaArray[index].ConnectionString);

		wprintf_s(L"\n");
	}

e_Exit:
	if (storageSchemaArray != NULL)
	{
		WinBioFree(storageSchemaArray);
		storageSchemaArray = NULL;
	}

	wprintf_s(L"\nPress any key to exit...");
	_getch();
	return hr;
}

HRESULT EnumSvcProviders()
{
	// Declare variables.
	HRESULT hr = S_OK;
	PWINBIO_BSP_SCHEMA bspSchemaArray = NULL;
	SIZE_T bspCount = 0;
	SIZE_T index = 0;

	// Enumerate the service providers.
	hr = WinBioEnumServiceProviders(
		WINBIO_TYPE_FINGERPRINT,    // Provider to enumerate
		&bspSchemaArray,            // Provider schema array
		&bspCount);                // Number of schemas returned
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioEnumServiceProviders failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Display the schema information.
	wprintf_s(L"\nService providers: \n");
	for (index = 0; index < bspCount; ++index)
	{
		wprintf_s(L"\n[%lld]: \tBiometric factor: 0x%08x\n",
			index,
			bspSchemaArray[index].BiometricFactor);

		wprintf_s(L"\tBspId: ");
		DisplayGuid(&bspSchemaArray[index].BspId);
		wprintf_s(L"\n");

		wprintf_s(L"\tDescription: %ws\n",
			bspSchemaArray[index].Description);
		wprintf_s(L"\tVendor: %ws\n",
			bspSchemaArray[index].Vendor);
		wprintf_s(L"\tVersion: %d.%d\n",
			bspSchemaArray[index].Version.MajorVersion,
			bspSchemaArray[index].Version.MinorVersion);

		wprintf_s(L"\n");
	}

e_Exit:
	if (bspSchemaArray != NULL)
	{
		WinBioFree(bspSchemaArray);
		bspSchemaArray = NULL;
	}

	wprintf_s(L"\nPress any key to exit...");
	_getch();
	return hr;
}

void CALLBACK WINBIO_ASYNC_COMPLETION_CALLBACK(PWINBIO_ASYNC_RESULT AsyncResult)
{
	wprintf_s(L"Operation Type [%d]\n", AsyncResult->Operation);
	wprintf_s(L"Sequence Number [%lld]\n", AsyncResult->SequenceNumber);

	FILETIME stFileTime;
	stFileTime.dwHighDateTime = (DWORD)(AsyncResult->TimeStamp >> 32);
	stFileTime.dwLowDateTime = (DWORD)(AsyncResult->TimeStamp & 0xFFFFFFFF);

	SYSTEMTIME stSystemTime;
	FileTimeToSystemTime(&stFileTime, &stSystemTime);

	wprintf_s(L"Time Stamp [%d/%02d/%02d(%d) %02d:%02d:%02d.%03d]\n",
		stSystemTime.wYear, stSystemTime.wMonth, stSystemTime.wDay, stSystemTime.wDayOfWeek,
		stSystemTime.wHour, stSystemTime.wMinute, stSystemTime.wSecond, stSystemTime.wMilliseconds);

	wprintf_s(L"API Status [0x%08X]\n", AsyncResult->ApiStatus);
	wprintf_s(L"Unit ID [%d]\n", AsyncResult->UnitId);
	wprintf_s(L"\n");
	WinBioFree(AsyncResult);
}

HRESULT WinbioAsyncLocateSensor()
{
	HRESULT hr = S_OK;
	WINBIO_SESSION_HANDLE sessionHandle = NULL;

	setlocale(LC_ALL, "Taiwan");

	hr = WinBioAsyncOpenSession(
		WINBIO_TYPE_FINGERPRINT,
		WINBIO_POOL_SYSTEM,
		WINBIO_FLAG_DEFAULT,
		NULL,
		0,
		WINBIO_DB_DEFAULT,
		WINBIO_ASYNC_NOTIFY_CALLBACK,
		NULL,
		0,
		WINBIO_ASYNC_COMPLETION_CALLBACK,
		NULL,
		FALSE,
		&sessionHandle
	);
	if (FAILED(hr))
	{
		wprintf_s(L"WinBioAsyncOpenSession failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	wprintf_s(L"Swipe your finger on the sensor...\n");
	hr = WinBioLocateSensor(sessionHandle, NULL);
	if (FAILED(hr))
	{
		wprintf_s(L"WinBioLocateSensor failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	_getch();

e_Exit:
	if (sessionHandle != NULL)
	{
		WinBioCloseSession(sessionHandle);
		sessionHandle = NULL;
	}
	return hr;
}

int EnumerateSensors(WINBIO_UNIT_ID *pUnitID, bool ShowMessage)
{
	HRESULT hr = S_OK;
	PWINBIO_UNIT_SCHEMA unitSchema = NULL;
	SIZE_T unitCount = 0;
	SIZE_T index = 0;

	// Enumerate the installed biometric units.
	hr = WinBioEnumBiometricUnits(
		WINBIO_TYPE_FINGERPRINT,        // Type of biometric unit
		&unitSchema,                    // Array of unit schemas
		&unitCount);                   // Count of unit schemas

	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioEnumBiometricUnits failed. hr = 0x%x\n", hr);
		//return FALSE;
		return -999;
	}

	if (unitCount >= 1)
		*pUnitID = unitSchema[0].UnitId;

	if (ShowMessage)
	{
		for (index = 0; index < unitCount; ++index)
		{
			wprintf_s(L"[%d] => Unit ID: %d", index, unitSchema[index].UnitId);
			wprintf_s(L"Device instance ID: %s", unitSchema[index].DeviceInstanceId);
			wprintf_s(L"Pool type: %d [%s]", unitSchema[index].PoolType, unitSchema[index].PoolType == WINBIO_POOL_SYSTEM ? _T("System") : _T("-"));
			wprintf_s(L"Biometric factor: %d [%s]", unitSchema[index].BiometricFactor, unitSchema[index].BiometricFactor == WINBIO_TYPE_FINGERPRINT ? _T("Fingerprint") : _T("-"));
			wprintf_s(L"Sensor subtype: %d [%s]", unitSchema[index].SensorSubType, unitSchema[index].SensorSubType == WINBIO_FP_SENSOR_SUBTYPE_TOUCH ? _T("Touch") : _T("-"));
			wprintf_s(L"Sensor capabilities: 0x%08x [%s]", unitSchema[index].Capabilities, unitSchema[index].Capabilities == WINBIO_CAPABILITY_SENSOR ? _T("Sensor") : _T("-"));
			wprintf_s(L"Description: %s", unitSchema[index].Description);
			wprintf_s(L"Manufacturer: %s", unitSchema[index].Manufacturer);
			wprintf_s(L"Model: %s", unitSchema[index].Model);
			wprintf_s(L"Serial no: %s", unitSchema[index].SerialNumber);
			wprintf_s(L"Firmware version: [%d.%d]", unitSchema[index].FirmwareVersion.MajorVersion, unitSchema[index].FirmwareVersion.MinorVersion);
		}
	}

	if (unitSchema != NULL)
	{
		WinBioFree(unitSchema);
		unitSchema = NULL;
	}
	return (int)unitCount;
}

HRESULT DeleteTemplate()
{
	HRESULT hr = S_OK;
	WINBIO_IDENTITY identity = { 0 };
	WINBIO_SESSION_HANDLE sessionHandle = NULL;
	WINBIO_UNIT_ID unitId = 0;
	PWINBIO_BIOMETRIC_SUBTYPE subFactorArray = NULL;
	SIZE_T subFactorCount = 0;
	WINBIO_BIOMETRIC_SUBTYPE subFactor = WINBIO_SUBTYPE_NO_INFORMATION;

	// Find the identity of the user.
	hr = GetCurrentUserIdentity(&identity);
	if (FAILED(hr))
	{
		wprintf_s(L"\n User identity not found. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Connect to the system pool. 
	//
	hr = WinBioOpenSession(
		WINBIO_TYPE_FINGERPRINT,    // Service provider
		WINBIO_POOL_SYSTEM,         // Pool type
		WINBIO_FLAG_DEFAULT,        // Configuration and access
		NULL,                       // Array of biometric unit IDs
		0,                          // Count of biometric unit IDs
		NULL,                       // Database ID
		&sessionHandle              // [out] Session handle
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioEnumBiometricUnits failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Locate the sensor.
	//
	//wprintf_s(L"\n Swipe your finger on the sensor...\n");
	//hr = WinBioLocateSensor(sessionHandle, &unitId);
	//if (FAILED(hr))
	//{
	//	wprintf_s(L"\n WinBioLocateSensor failed. hr = 0x%x\n", hr);
	//	goto e_Exit;
	//}

	EnumerateSensors(&unitId, false);
	wprintf_s(L"\n Enrollments for this user on Unit ID %d:", unitId);

	// Retrieve the biometric sub-factors for the template.
	hr = WinBioEnumEnrollments(
		sessionHandle,              // Session handle
		unitId,                     // Biometric unit ID
		&identity,                  // Template ID
		&subFactorArray,            // Subfactors
		&subFactorCount             // Count of subfactors
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioEnumEnrollments failed. hr = 0x%x", hr);
		wprintf_s(L"\n The biometric sample doesn't match any known identity.\n");
		goto e_Exit;
	}
	wprintf_s(L"\n subFactorCount %d:", subFactorCount);

	for (SIZE_T index = 0; index < subFactorCount; ++index)
	{
		subFactor = subFactorArray[index];
		wprintf_s(L"\n subFactorArray[%d] %d:", index, subFactorArray[index]);
		wprintf_s(L"\n subFactor %d:", subFactor);

		// Delete the template identified by the subFactor argument.
		//
		hr = WinBioDeleteTemplate(
			sessionHandle,
			unitId,
			&identity,
			subFactor
		);
		if (FAILED(hr))
		{
			wprintf_s(L"\n WinBioDeleteTemplate failed. hr = 0x%x\n", hr);
			goto e_Exit;
		}
		else
		{
			wprintf_s(L"\n Delete %d Template Success\n", subFactor);
		}
	}

e_Exit:
	if (subFactorArray != NULL)
	{
		WinBioFree(subFactorArray);
		subFactorArray = NULL;
	}

	if (sessionHandle != NULL)
	{
		WinBioCloseSession(sessionHandle);
		sessionHandle = NULL;
	}

	//wprintf_s(L"\n Press any key to exit...");
	//_getch();
	return hr;
}

HRESULT DeleteTemplate(WINBIO_BIOMETRIC_SUBTYPE subFactor)
{
	HRESULT hr = S_OK;
	WINBIO_IDENTITY identity = { 0 };
	WINBIO_SESSION_HANDLE sessionHandle = NULL;
	WINBIO_UNIT_ID unitId = 0;

	// Find the identity of the user.
	hr = GetCurrentUserIdentity(&identity);
	if (FAILED(hr))
	{
		wprintf_s(L"\n User identity not found. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Connect to the system pool. 
	//
	hr = WinBioOpenSession(
		WINBIO_TYPE_FINGERPRINT,    // Service provider
		WINBIO_POOL_SYSTEM,         // Pool type
		WINBIO_FLAG_DEFAULT,        // Configuration and access
		NULL,                       // Array of biometric unit IDs
		0,                          // Count of biometric unit IDs
		NULL,                       // Database ID
		&sessionHandle              // [out] Session handle
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioEnumBiometricUnits failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Locate the sensor.
	//
	//wprintf_s(L"\n Swipe your finger on the sensor...\n");
	//hr = WinBioLocateSensor(sessionHandle, &unitId);
	//if (FAILED(hr))
	//{
	//	wprintf_s(L"\n WinBioLocateSensor failed. hr = 0x%x\n", hr);
	//	goto e_Exit;
	//}

	EnumerateSensors(&unitId, false);
	wprintf_s(L"\n Enrollments for this user on Unit ID %d:", unitId);
	
	// Delete the template identified by the subFactor argument.
	//
	hr = WinBioDeleteTemplate(
		sessionHandle,
		unitId,
		&identity,
		subFactor
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioDeleteTemplate failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

e_Exit:
	if (sessionHandle != NULL)
	{
		WinBioCloseSession(sessionHandle);
		sessionHandle = NULL;
	}

	wprintf_s(L"Press any key to exit...");
	_getch();

	return hr;
}

//------------------------------------------------------------------------
// The following function enrolls a user's fingerprint in the system pool.
// The function calls WinBioEnrollCaptureWithCallback and waits for the
// asynchronous enrollment process to be completed or canceled.
//
HRESULT EnrollSysPoolWithCallback(
	BOOL bCancel,
	BOOL bDiscard,
	WINBIO_BIOMETRIC_SUBTYPE subFactor)
{
	// Declare variables
	HRESULT hr = S_OK;
	WINBIO_IDENTITY identity = { 0 };
	WINBIO_SESSION_HANDLE sessionHandle = NULL;
	WINBIO_UNIT_ID unitId = 0;
	BOOLEAN isNewTemplate = TRUE;
	ENROLL_CALLBACK_CONTEXT callbackContext = { 0 };

	// Connect to the system pool. 
	hr = WinBioOpenSession(
		WINBIO_TYPE_FINGERPRINT,    // Service provider
		WINBIO_POOL_SYSTEM,         // Pool type
		WINBIO_FLAG_DEFAULT,        // Configuration and access
		NULL,                       // Array of biometric unit IDs
		0,                          // Count of biometric unit IDs
		NULL,                       // Database ID
		&sessionHandle              // [out] Session handle
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioEnumBiometricUnits failed. ");
		wprintf_s(L"hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Locate the sensor.
	wprintf_s(L"\n Swipe your finger to locate the sensor...\n");
	hr = WinBioLocateSensor(sessionHandle, &unitId);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioLocateSensor failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Begin the enrollment sequence. 
	hr = WinBioEnrollBegin(
		sessionHandle,      // Handle to open biometric session
		subFactor,          // Finger to create template for
		unitId              // Biometric unit ID
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioEnrollBegin failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Set up the custom callback context structure.
	callbackContext.SessionHandle = sessionHandle;
	callbackContext.UnitId = unitId;
	callbackContext.SubFactor = subFactor;

	// Call WinBioEnrollCaptureWithCallback. This is an asynchronous
	// method that returns immediately.
	hr = WinBioEnrollCaptureWithCallback(
		sessionHandle,          // Handle to open biometric session
		EnrollCaptureCallback,  // Callback function
		&callbackContext        // Pointer to the custom context
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioEnrollCaptureWithCallback failed. ");
		wprintf_s(L"hr = 0x%x\n", hr);
		goto e_Exit;
	}
	wprintf_s(L"\n Swipe the sensor with the appropriate finger...\n");

	// Cancel the enrollment if the bCancel flag is set.
	if (bCancel)
	{
		wprintf_s(L"\n Starting CANCEL timer...\n");
		Sleep(7000);

		wprintf_s(L"\n Calling WinBioCancel\n");
		hr = WinBioCancel(sessionHandle);
		if (FAILED(hr))
		{
			wprintf_s(L"\n WinBioCancel failed. hr = 0x%x\n", hr);
			goto e_Exit;
		}
	}

	// Wait for the asynchronous enrollment process to complete
	// or be canceled.
	hr = WinBioWait(sessionHandle);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioWait failed. hr = 0x%x\n", hr);
	}

	// Discard the enrollment if the bDiscard flag is set.
	// Commit the enrollment if the flag is not set.
	if (bDiscard)
	{
		wprintf_s(L"\n Discarding enrollment...\n");
		hr = WinBioEnrollDiscard(sessionHandle);
		if (FAILED(hr))
		{
			wprintf_s(L"\n WinBioLocateSensor failed. ");
			wprintf_s(L"hr = 0x%x\n", hr);
		}
		goto e_Exit;
	}
	else
	{
		wprintf_s(L"\n Committing enrollment...\n");
		hr = WinBioEnrollCommit(
			sessionHandle,      // Handle to open biometric session
			&identity,          // WINBIO_IDENTITY object for the user
			&isNewTemplate);    // Is this a new template

		if (FAILED(hr))
		{
			wprintf_s(L"\n WinBioEnrollCommit failed. hr = 0x%x\n", hr);
			goto e_Exit;
		}
	}

e_Exit:
	if (sessionHandle != NULL)
	{
		WinBioCloseSession(sessionHandle);
		sessionHandle = NULL;
	}

	wprintf_s(L"\n Press any key to exit...");
	_getch();

	return hr;
}

//------------------------------------------------------------------------
// The following function is the callback for the Windows Biometric
// Framework WinBioEnrollCaptureWithCallback() function. 
//
VOID CALLBACK EnrollCaptureCallback(
	__in_opt PVOID EnrollCallbackContext,
	__in HRESULT OperationStatus,
	__in WINBIO_REJECT_DETAIL RejectDetail
)
{
	// Declare variables.
	HRESULT hr = S_OK;
	static SIZE_T swipeCount = 1;

	PENROLL_CALLBACK_CONTEXT callbackContext =
		(PENROLL_CALLBACK_CONTEXT)EnrollCallbackContext;

	wprintf_s(L"\n EnrollCaptureCallback executing\n");
	wprintf_s(L"\n Sample %d captured", swipeCount++);

	// The capture was not acceptable or the enrollment operation
	// failed.
	if (FAILED(OperationStatus))
	{
		if (OperationStatus == WINBIO_E_BAD_CAPTURE)
		{
			wprintf_s(L"\n Bad capture; reason: %d. (%ws)\n", RejectDetail, ConvertRejectDetailToString(RejectDetail));
			wprintf_s(L"\n Swipe your finger to capture another sample.\n");

			// Try again.
			hr = WinBioEnrollCaptureWithCallback(
				callbackContext->SessionHandle, // Open session handle
				EnrollCaptureCallback,          // Callback function
				EnrollCallbackContext           // Callback context
			);
			if (FAILED(hr))
			{
				wprintf_s(L"WinBioEnrollCaptureWithCallback failed.");
				wprintf_s(L"hr = 0x%x\n", hr);
			}
		}
		else
		{
			wprintf_s(L"EnrollCaptureCallback failed.");
			wprintf_s(L"OperationStatus = 0x%x\n", OperationStatus);
		}
		goto e_Exit;
	}

	// The enrollment operation requires more fingerprint swipes.
	// This is normal and depends on your hardware. Typically, at least
	// three swipes are required.
	if (OperationStatus == WINBIO_I_MORE_DATA)
	{
		wprintf_s(L"\n More data required.");
		wprintf_s(L"\n Swipe your finger on the sensor again.");

		hr = WinBioEnrollCaptureWithCallback(
			callbackContext->SessionHandle,
			EnrollCaptureCallback,
			EnrollCallbackContext
		);
		if (FAILED(hr))
		{
			wprintf_s(L"WinBioEnrollCaptureWithCallback failed. ");
			wprintf_s(L"hr = 0x%x\n", hr);
		}
		goto e_Exit;
	}

	wprintf_s(L"\n Template completed\n");

e_Exit:

	return;
}

HRESULT CaptureSampleWithCallback(BOOL bCancel)
{
	HRESULT hr = S_OK;
	WINBIO_SESSION_HANDLE sessionHandle = NULL;

	// Connect to the system pool. 
	hr = WinBioOpenSession(
		WINBIO_TYPE_FINGERPRINT,    // Service provider
		WINBIO_POOL_SYSTEM,         // Pool type
		WINBIO_FLAG_RAW,            // Raw access
		NULL,                       // Array of biometric unit IDs
		0,                          // Count of biometric unit IDs
		WINBIO_DB_DEFAULT,          // Default database
		&sessionHandle              // [out] Session handle
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioOpenSession failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Capture a biometric sample asynchronously.
	wprintf_s(L"\n Calling WinBioCaptureSampleWithCallback ");
	hr = WinBioCaptureSampleWithCallback(
		sessionHandle,                  // Open session handle
		WINBIO_NO_PURPOSE_AVAILABLE,    // Intended use of the sample
		WINBIO_DATA_FLAG_RAW,           // Sample format
		CaptureSampleCallback,          // Callback function
		NULL                            // Optional context
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioCaptureSampleWithCallback failed. ");
		wprintf_s(L"hr = 0x%x\n", hr);
		goto e_Exit;
	}
	wprintf_s(L"\n Swipe the sensor ...\n");

	// Cancel the capture process if the bCancel flag is set.
	if (bCancel)
	{
		wprintf_s(L"\n Starting CANCEL timer...");
		Sleep(7000);

		wprintf_s(L"\n Calling WinBioCancel\n");
		hr = WinBioCancel(sessionHandle);
		if (FAILED(hr))
		{
			wprintf_s(L"\n WinBioCancel failed. hr = 0x%x\n", hr);
			goto e_Exit;
		}
	}

	// Wait for the asynchronous capture process to complete 
	// or be canceled.
	hr = WinBioWait(sessionHandle);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioWait failed. hr = 0x%x\n", hr);
	}

e_Exit:

	if (sessionHandle != NULL)
	{
		WinBioCloseSession(sessionHandle);
		sessionHandle = NULL;
	}

	wprintf_s(L"\n Press any key to exit...");
	_getch();

	return hr;
}

//------------------------------------------------------------------------
// The following function is the callback for WinBioCaptureSampleWithCallback.
// The function filters the response from the biometric subsystem and 
// writes a result to the console window.
//
VOID CALLBACK CaptureSampleCallback(
	__in_opt PVOID CaptureCallbackContext,
	__in HRESULT OperationStatus,
	__in WINBIO_UNIT_ID UnitId,
	__in_bcount(SampleSize) PWINBIO_BIR Sample,
	__in SIZE_T SampleSize,
	__in WINBIO_REJECT_DETAIL RejectDetail
)
{
	UNREFERENCED_PARAMETER(CaptureCallbackContext);

	wprintf_s(L"\n CaptureSampleCallback executing");
	wprintf_s(L"\n Swipe processed - Unit ID: %d", UnitId);

	if (FAILED(OperationStatus))
	{
		if (OperationStatus == WINBIO_E_BAD_CAPTURE)
		{
			wprintf_s(L"\n Bad capture; reason: %d\n", RejectDetail);
		}
		else
		{
			wprintf_s(L"\n WinBioCaptureSampleWithCallback failed. ");
			wprintf_s(L" OperationStatus = 0x%x\n", OperationStatus);
		}
		goto e_Exit;
	}

	wprintf_s(L"\n Captured %d bytes.\n", SampleSize);

e_Exit:

	if (Sample != NULL)
	{
		WinBioFree(Sample);
		Sample = NULL;
	}
}

HRESULT GetCredentialState()
{
	// Declare variables.
	HRESULT hr = S_OK;
	WINBIO_IDENTITY identity;
	WINBIO_CREDENTIAL_STATE credState;

	// Find the identity of the user.
	wprintf_s(L"\n Finding user identity.\n");
	hr = GetCurrentUserIdentity(&identity);
	if (FAILED(hr))
	{
		wprintf_s(L"\n User identity not found. hr = 0x%x\n", hr);
		return hr;
	}

	// Find the credential state for the user.
	wprintf_s(L"\n Calling WinBioGetCredentialState.\n");
	hr = WinBioGetCredentialState(
		identity,                      // User GUID or SID
		WINBIO_CREDENTIAL_PASSWORD,    // Credential type
		&credState                     // [out] Credential state
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioGetCredentialState failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Print the credential state.
	switch (credState)
	{
	case WINBIO_CREDENTIAL_SET:
		wprintf_s(L"\n Credential set.\n");
		break;
	case WINBIO_CREDENTIAL_NOT_SET:
		wprintf_s(L"\n Credential NOT set.\n");
		break;
	default:
		wprintf_s(L"\n ERROR: Invalid credential state.\n");
		hr = E_FAIL;
	}

e_Exit:

	wprintf_s(L"\n Press any key to exit...");
	_getch();

	return hr;

}

HRESULT VerifyWithCallback(BOOL bCancel, WINBIO_BIOMETRIC_SUBTYPE subFactor)
{
	// Declare variables.
	HRESULT hr = S_OK;
	WINBIO_SESSION_HANDLE sessionHandle = NULL;
	WINBIO_UNIT_ID unitId = 0;
	WINBIO_REJECT_DETAIL rejectDetail = 0;
	WINBIO_IDENTITY identity = { 0 };

	// Find the identity of the user.
	hr = GetCurrentUserIdentity(&identity);
	if (FAILED(hr))
	{
		wprintf_s(L"\n User identity not found. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Connect to the system pool. 
	hr = WinBioOpenSession(
		WINBIO_TYPE_FINGERPRINT,    // Service provider
		WINBIO_POOL_SYSTEM,         // Pool type
		WINBIO_FLAG_DEFAULT,        // Configuration and access
		NULL,                       // Array of biometric unit IDs
		0,                          // Count of biometric unit IDs
		NULL,                       // Database ID
		&sessionHandle              // [out] Session handle
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioOpenSession failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Verify a biometric sample asynchronously.
	wprintf_s(L"\n Calling WinBioVerifyWithCallback.\n");
	hr = WinBioVerifyWithCallback(
		sessionHandle,              // Open session handle
		&identity,                  // User SID or GUID
		subFactor,                  // Sample sub-factor
		VerifyCallback,             // Callback function
		NULL                        // Optional context
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioVerifyWithCallback failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}
	wprintf_s(L"\n Swipe the sensor ...\n");

	// Cancel the identification if the bCancel flag is set.
	if (bCancel)
	{
		wprintf_s(L"\n Starting CANCEL timer...\n");
		Sleep(7000);

		wprintf_s(L"\n Calling WinBioCancel\n");
		hr = WinBioCancel(sessionHandle);
		if (FAILED(hr))
		{
			wprintf_s(L"\n WinBioCancel failed. hr = 0x%x\n", hr);
			goto e_Exit;
		}
	}

	// Wait for the asynchronous identification process to complete 
	// or be canceled.
	hr = WinBioWait(sessionHandle);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioWait failed. hr = 0x%x\n", hr);
	}

e_Exit:
	if (sessionHandle != NULL)
	{
		WinBioCloseSession(sessionHandle);
		sessionHandle = NULL;
	}

	wprintf_s(L"\n Hit any key to continue...");
	_getch();

	return hr;
}

//------------------------------------------------------------------------
// The following function is the callback for WinBioVerifyWithCallback.
// The function filters the response from the biometric subsystem and 
// writes a result to the console window.
// 
VOID CALLBACK VerifyCallback(
	__in_opt PVOID VerifyCallbackContext,
	__in HRESULT OperationStatus,
	__in WINBIO_UNIT_ID UnitId,
	__in BOOLEAN Match,
	__in WINBIO_REJECT_DETAIL RejectDetail
)
{
	UNREFERENCED_PARAMETER(VerifyCallbackContext);
	UNREFERENCED_PARAMETER(Match);

	wprintf_s(L"\n VerifyCallback executing");
	wprintf_s(L"\n Swipe processed for unit ID %d\n", UnitId);

	// The identity could not be verified.
	if (FAILED(OperationStatus))
	{
		wprintf_s(L"\n Verification failed for the following reason:");
		if (OperationStatus == WINBIO_E_NO_MATCH)
		{
			wprintf_s(L"\n No match.\n");
		}
		else if (OperationStatus == WINBIO_E_BAD_CAPTURE)
		{
			wprintf_s(L"\n Bad capture.\n ");
			wprintf_s(L"\n Bad capture; reason: %d\n", RejectDetail);
		}
		else
		{
			wprintf_s(L"VerifyCallback failed.");
			wprintf_s(L"OperationStatus = 0x%x\n", OperationStatus);
		}
		goto e_Exit;
	}

	// The user identity was verified.
	wprintf_s(L"\n Fingerprint verified:\n");

e_Exit:
	return;
}

HRESULT IdentifyWithCallback(BOOL bCancel)
{
	// Declare variables.
	HRESULT hr = S_OK;
	WINBIO_SESSION_HANDLE sessionHandle = NULL;

	// Connect to the system pool. 
	hr = WinBioOpenSession(
		WINBIO_TYPE_FINGERPRINT,    // Service provider
		WINBIO_POOL_SYSTEM,         // Pool type 
		WINBIO_FLAG_DEFAULT,        // Configuration and access 
		NULL,                       // Array of biometric unit IDs 
		0,                          // Count of biometric unit IDs 
		WINBIO_DB_DEFAULT,          // Database ID 
		&sessionHandle              // [out] Session handle
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioOpenSession failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Call WinBioIdentifyWithCallback. The method is asynchronous
	// and returns immediately.
	wprintf_s(L"\n Calling WinBioIdentifyWithCallback");
	wprintf_s(L"\n Swipe the sensor ...\n");
	hr = WinBioIdentifyWithCallback(
		sessionHandle,              // Open biometric session
		IdentifyCallback,           // Callback function
		NULL                        // Optional context
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioIdentifyWithCallback failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Cancel user identification if the bCancel flag is set.
	if (bCancel)
	{
		wprintf_s(L"\n Starting CANCEL timer...\n");
		Sleep(7000);

		wprintf_s(L"\n Calling WinBioCancel\n");
		hr = WinBioCancel(sessionHandle);
		if (FAILED(hr))
		{
			wprintf_s(L"\n WinBioCancel failed. hr = 0x%x\n", hr);
			goto e_Exit;
		}
	}

	// Wait for the asynchronous identification process to complete 
	// or be canceled.
	hr = WinBioWait(sessionHandle);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioWait failed. hr = 0x%x\n", hr);
	}

e_Exit:

	if (sessionHandle != NULL)
	{
		wprintf_s(L"\n Closing the session.\n");

		hr = WinBioCloseSession(sessionHandle);
		if (FAILED(hr))
		{
			wprintf_s(L"\n WinBioCloseSession failed. hr = 0x%x\n", hr);
		}
		sessionHandle = NULL;
	}

	wprintf_s(L"\n Hit any key to exit...");
	_getch();

	return hr;
}

//------------------------------------------------------------------------
// The following function is the callback for WinBioIdentifyWithCallback.
// The function filters the response from the biometric subsystem and 
// writes a result to the console window.
// 
VOID CALLBACK IdentifyCallback(
	__in_opt PVOID IdentifyCallbackContext,
	__in HRESULT OperationStatus,
	__in WINBIO_UNIT_ID UnitId,
	__in WINBIO_IDENTITY *Identity,
	__in WINBIO_BIOMETRIC_SUBTYPE SubFactor,
	__in WINBIO_REJECT_DETAIL RejectDetail
)
{
	UNREFERENCED_PARAMETER(IdentifyCallbackContext);
	UNREFERENCED_PARAMETER(Identity);

	wprintf_s(L"\n IdentifyCallback executing");
	wprintf_s(L"\n Swipe processed for unit ID %d\n", UnitId);

	// The attempt to process the fingerprint failed.
	if (FAILED(OperationStatus))
	{
		if (OperationStatus == WINBIO_E_UNKNOWN_ID)
		{
			wprintf_s(L"\n Unknown identity.\n");
		}
		else if (OperationStatus == WINBIO_E_BAD_CAPTURE)
		{
			wprintf_s(L"\n Bad capture; reason: %d\n", RejectDetail);
		}
		else
		{
			wprintf_s(L"IdentifyCallback failed.");
			wprintf_s(L"OperationStatus = 0x%x\n", OperationStatus);
		}
	}
	// Processing succeeded and the finger swiped is written
	// to the console window.
	else
	{
		wprintf_s(L"\n The following finger was used:");
		switch (SubFactor)
		{
			case WINBIO_SUBTYPE_NO_INFORMATION:
				wprintf_s(L"\n No information\n");
				break;
			case WINBIO_ANSI_381_POS_RH_THUMB:
				wprintf_s(L"\n RH thumb\n");
				break;
			case WINBIO_ANSI_381_POS_RH_INDEX_FINGER:
				wprintf_s(L"\n RH index finger\n");
				break;
			case WINBIO_ANSI_381_POS_RH_MIDDLE_FINGER:
				wprintf_s(L"\n RH middle finger\n");
				break;
			case WINBIO_ANSI_381_POS_RH_RING_FINGER:
				wprintf_s(L"\n RH ring finger\n");
				break;
			case WINBIO_ANSI_381_POS_RH_LITTLE_FINGER:
				wprintf_s(L"\n RH little finger\n");
				break;
			case WINBIO_ANSI_381_POS_LH_THUMB:
				wprintf_s(L"\n LH thumb\n");
				break;
			case WINBIO_ANSI_381_POS_LH_INDEX_FINGER:
				wprintf_s(L"\n LH index finger\n");
				break;
			case WINBIO_ANSI_381_POS_LH_MIDDLE_FINGER:
				wprintf_s(L"\n LH middle finger\n");
				break;
			case WINBIO_ANSI_381_POS_LH_RING_FINGER:
				wprintf_s(L"\n LH ring finger\n");
				break;
			case WINBIO_ANSI_381_POS_LH_LITTLE_FINGER:
				wprintf_s(L"\n LH little finger\n");
				break;
			case WINBIO_SUBTYPE_ANY:
				wprintf_s(L"\n Any finger\n");
				break;
			default:
				break;
		}
	}
}

HRESULT LocateSensorWithCallback(BOOL bCancel)
{
	HRESULT hr = S_OK;
	WINBIO_SESSION_HANDLE sessionHandle = NULL;
	WINBIO_UNIT_ID unitId = 0;

	// Connect to the system pool. 
	hr = WinBioOpenSession(
		WINBIO_TYPE_FINGERPRINT,    // Service provider
		WINBIO_POOL_SYSTEM,         // Pool type
		WINBIO_FLAG_DEFAULT,        // Configuration and access
		NULL,                       // Array of biometric unit IDs
		0,                          // Count of biometric unit IDs
		NULL,                       // Database ID
		&sessionHandle              // [out] Session handle
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioOpenSession failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	wprintf_s(L"\n Calling WinBioLocateSensorWithCallback.");
	hr = WinBioLocateSensorWithCallback(
		sessionHandle,          // Open biometric session
		LocateSensorCallback,   // Callback function
		NULL                    // Optional context
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioLocateSensorWithCallback failed.");
		wprintf_s(L"hr = 0x%x\n", hr);
		goto e_Exit;
	}
	wprintf_s(L"\n Swipe the sensor ...\n");

	// Cancel the identification if the bCancel flag is set.
	if (bCancel)
	{
		wprintf_s(L"\n Starting CANCEL timer...\n");
		Sleep(7000);

		wprintf_s(L"\n Calling WinBioCancel\n");
		hr = WinBioCancel(sessionHandle);
		if (FAILED(hr))
		{
			wprintf_s(L"\n WinBioCancel failed. hr = 0x%x\n", hr);
			goto e_Exit;
		}
	}

	// Wait for the asynchronous identification process to complete 
	// or be canceled.
	hr = WinBioWait(sessionHandle);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioWait failed. hr = 0x%x\n", hr);
	}

e_Exit:

	if (sessionHandle != NULL)
	{
		wprintf_s(L"\n Closing the session.\n");

		hr = WinBioCloseSession(sessionHandle);
		if (FAILED(hr))
		{
			wprintf_s(L"\n WinBioCloseSession failed. hr = 0x%x\n", hr);
		}
		sessionHandle = NULL;
	}

	wprintf_s(L"\n Hit any key to exit...");
	_getch();

	return hr;
}

//------------------------------------------------------------------------
// The following function is the callback for 
// WinBioLocateSensorWithCallback. The function filters the response 
// from the biometric subsystem and writes a result to the console window.
// 
VOID CALLBACK LocateSensorCallback(
	__in_opt PVOID LocateCallbackContext,
	__in HRESULT OperationStatus,
	__in WINBIO_UNIT_ID UnitId
)
{
	UNREFERENCED_PARAMETER(LocateCallbackContext);

	wprintf_s(L"\n LocateSensorCallback executing.");

	// A sensor could not be located.
	if (FAILED(OperationStatus))
	{
		wprintf_s(L"\n LocateSensorCallback failed.");
		wprintf_s(L"OperationStatus = 0x%x\n", OperationStatus);
	}
	// A sensor was located.
	else
	{
		wprintf_s(L"\n Selected unit ID: %d\n", UnitId);
	}
}

HRESULT EnumEnrollments(PWINBIO_BIOMETRIC_SUBTYPE _subFactorArray, SIZE_T *_subFactorCount)
{
	// Declare variables.
	HRESULT hr = S_OK;
	WINBIO_IDENTITY identity = { 0 };
	WINBIO_SESSION_HANDLE sessionHandle = NULL;
	WINBIO_UNIT_ID unitId = 0;
	PWINBIO_BIOMETRIC_SUBTYPE subFactorArray = NULL;
	WINBIO_BIOMETRIC_SUBTYPE SubFactor = 0;
	SIZE_T subFactorCount = 0;
	WINBIO_REJECT_DETAIL rejectDetail = 0;
	WINBIO_BIOMETRIC_SUBTYPE subFactor = WINBIO_SUBTYPE_NO_INFORMATION;

	// Find the identity of the user.
	hr = GetCurrentUserIdentity(&identity);
	if (FAILED(hr))
	{
		wprintf_s(L"\n User identity not found. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	// Connect to the system pool. 
	hr = WinBioOpenSession(
		WINBIO_TYPE_FINGERPRINT,    // Service provider
		WINBIO_POOL_SYSTEM,         // Pool type
		WINBIO_FLAG_DEFAULT,        // Configuration and access
		NULL,                       // Array of biometric unit IDs
		0,                          // Count of biometric unit IDs
		NULL,                       // Database ID
		&sessionHandle              // [out] Session handle
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioOpenSession failed. hr = 0x%x\n", hr);
		goto e_Exit;
	}

	EnumerateSensors(&unitId, false);

	// Locate the biometric sensor and retrieve a WINBIO_IDENTITY object.
//	wprintf_s(L"\n Calling WinBioIdentify - Swipe finger on sensor...\n");
//	hr = WinBioIdentify(
//		sessionHandle,              // Session handle
//		&unitId,                    // Biometric unit ID
//		&identity,                  // User SID
//		&subFactor,                 // Finger sub factor
//		&rejectDetail               // Rejection information
//	);
//	wprintf_s(L"\n Swipe processed - Unit ID: %d\n", unitId);
//	if (FAILED(hr))
//	{
//		if (hr == WINBIO_E_UNKNOWN_ID)
//		{
//			wprintf_s(L"\n Unknown identity.\n");
//		}
//		else if (hr == WINBIO_E_BAD_CAPTURE)
//		{
//			wprintf_s(L"\n Bad capture; reason: %d. (%s)\n", rejectDetail, ConvertRejectDetailToString(rejectDetail));
//		}
//		else
//		{
//			wprintf_s(L"\n WinBioEnumBiometricUnits failed. hr = 0x%x\n", hr);
//		}
//		goto e_Exit;
//	}
//	else
//	{
//		wprintf_s(L"Biometric unit ID = 0x%x\n", unitId);
		//wprintf_s(L"User SID = %08x-%04x-%04x-%08x\n", identity.Value.TemplateGuid.Data1, identity.Value.TemplateGuid.Data2, identity.Value.TemplateGuid.Data3, identity.Value.TemplateGuid.Data4);
//		wprintf_s(L"User SID = %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
//			identity.Value.TemplateGuid.Data1,
//			identity.Value.TemplateGuid.Data2,
//			identity.Value.TemplateGuid.Data3,
//			identity.Value.TemplateGuid.Data4[0],
//			identity.Value.TemplateGuid.Data4[1],
//			identity.Value.TemplateGuid.Data4[2],
//			identity.Value.TemplateGuid.Data4[3],
//			identity.Value.TemplateGuid.Data4[4],
//			identity.Value.TemplateGuid.Data4[5],
//			identity.Value.TemplateGuid.Data4[6],
//			identity.Value.TemplateGuid.Data4[7]);
//		wprintf_s(L"Finger sub factor = 0x%x. (%s)\n", subFactor, ConvertSubFactorToString(subFactor));
//	}

	// Retrieve the biometric sub-factors for the template.
	hr = WinBioEnumEnrollments(
		sessionHandle,              // Session handle
		unitId,                     // Biometric unit ID
		&identity,                  // Template ID
		&subFactorArray,            // Subfactors
		&subFactorCount             // Count of subfactors
	);
	if (FAILED(hr))
	{
		wprintf_s(L"\n WinBioEnumEnrollments failed. hr = 0x%x\n", hr);
		if (hr == WINBIO_E_UNKNOWN_ID)
		{
			wprintf_s(L"\n Unknown identity.\n The biometric sample doesn't match any known identify.\n");
		}
		else if (hr == E_INVALIDARG) 
		{
			wprintf_s(L"\n The UnitId parameter cannot be zero.\n");
		}
		goto e_Exit;
	}

	// Print the sub-factor(s) to the console.
	wprintf_s(L"\n Enrollments for this user on Unit ID: %d", unitId);
	wprintf_s(L"\n Enrollments subFactorCount: %d\n", subFactorCount);
	*_subFactorCount = subFactorCount;

	for (SIZE_T index = 0; index < subFactorCount; ++index)
	{
		SubFactor = subFactorArray[index];
		_subFactorArray[index] = SubFactor;
		wprintf_s(L"SubFactor %d:", SubFactor);

		switch (SubFactor)
		{
			case WINBIO_ANSI_381_POS_RH_THUMB:
				wprintf_s(L"\n   RH thumb\n");
				break;
			case WINBIO_ANSI_381_POS_RH_INDEX_FINGER:
				wprintf_s(L"\n   RH index finger\n");
				break;
			case WINBIO_ANSI_381_POS_RH_MIDDLE_FINGER:
				wprintf_s(L"\n   RH middle finger\n");
				break;
			case WINBIO_ANSI_381_POS_RH_RING_FINGER:
				wprintf_s(L"\n   RH ring finger\n");
				break;
			case WINBIO_ANSI_381_POS_RH_LITTLE_FINGER:
				wprintf_s(L"\n   RH little finger\n");
				break;
			case WINBIO_ANSI_381_POS_LH_THUMB:
				wprintf_s(L"\n   LH thumb\n");
				break;
			case WINBIO_ANSI_381_POS_LH_INDEX_FINGER:
				wprintf_s(L"\n   LH index finger\n");
				break;
			case WINBIO_ANSI_381_POS_LH_MIDDLE_FINGER:
				wprintf_s(L"\n   LH middle finger\n");
				break;
			case WINBIO_ANSI_381_POS_LH_RING_FINGER:
				wprintf_s(L"\n   LH ring finger\n");
				break;
			case WINBIO_ANSI_381_POS_LH_LITTLE_FINGER:
				wprintf_s(L"\n   LH little finger\n");
				break;
			default:
				wprintf_s(L"\n   The sub-factor is not correct\n");
				break;
		}
	}

e_Exit:
	if (subFactorArray != NULL)
	{
		WinBioFree(subFactorArray);
		subFactorArray = NULL;
	}

	if (sessionHandle != NULL)
	{
		WinBioCloseSession(sessionHandle);
		sessionHandle = NULL;
	}

	//wprintf_s(L"\n Press any key to exit...");
	//_getch();
	return hr;
}

int main(char *argv[], int argc)
{
	char ch;
	int nSelect;
	int verifyCounter = 0;
	HRESULT hr = S_OK;
	WINBIO_BIOMETRIC_SUBTYPE subFactor;
	WINBIO_BIOMETRIC_SUBTYPE g_subFactorArray[10] = { 0 };
	SIZE_T g_subFactorCount = 0;
	BOOL g_bLoop = TRUE;

	setlocale(LC_ALL, "chinese-traditional");

	while (g_bLoop)
	{
		wprintf_s(L" Please Enter The Item:\n");
		wprintf_s(L" Item : Function\n");
		wprintf_s(L"   a -> Enroll\n");
		wprintf_s(L"   b -> Verify\n");
		wprintf_s(L"   c -> Identify\n");
		wprintf_s(L"   d -> CaptureSample\n");
		wprintf_s(L"   e -> EnumerateSensors\n");
		wprintf_s(L"   f -> LocateSensor\n");
		wprintf_s(L"   g -> EnumEnrollments\n");
		wprintf_s(L"   h -> EnumDatabases\n");
		wprintf_s(L"   i -> EnumSvcProviders\n");
		wprintf_s(L"   j -> DeleteTemplate\n");
		wprintf_s(L"   k -> EnumEnrollments(2)\n");
		wprintf_s(L"   q -> Quit\n");

		scanf(" %c", &ch);
		//ch = getchar();
		switch (ch)
		{
			//Enroll
			case 'a':
				wprintf_s(L" Enter Enroll Finger:\n");
				wprintf_s(L"  WINBIO_ANSI_381_POS_RH_THUMB        	1\n");
				wprintf_s(L"  WINBIO_ANSI_381_POS_RH_INDEX_FINGER 	2\n");
				wprintf_s(L"  WINBIO_ANSI_381_POS_RH_MIDDLE_FINGER	3\n");
				wprintf_s(L"  WINBIO_ANSI_381_POS_RH_RING_FINGER  	4\n");
				wprintf_s(L"  WINBIO_ANSI_381_POS_RH_LITTLE_FINGER	5\n");
				wprintf_s(L"  WINBIO_ANSI_381_POS_LH_THUMB        	6\n");
				wprintf_s(L"  WWINBIO_ANSI_381_POS_LH_INDEX_FINGER 	7\n");
				wprintf_s(L"  WINBIO_ANSI_381_POS_LH_MIDDLE_FINGER	8\n");
				wprintf_s(L"  WINBIO_ANSI_381_POS_LH_RING_FINGER  	9\n");
				wprintf_s(L"  WINBIO_ANSI_381_POS_LH_LITTLE_FINGER	10\n");
				std::cin >> nSelect;
				subFactor = (WINBIO_BIOMETRIC_SUBTYPE)nSelect;
				//subFactor = WINBIO_ANSI_381_POS_RH_THUMB;
				//EnrollSysPool(FALSE, subFactor);
				//hr = EnrollSysPoolWithCallback(FALSE, FALSE, WINBIO_ANSI_381_POS_RH_INDEX_FINGER);
				hr = EnrollSysPoolWithCallback(FALSE, FALSE, subFactor);
				break;

				//Verify
			case 'b':
				wprintf_s(L" Enter Verify Finger:\n");
				wprintf_s(L"  WINBIO_ANSI_381_POS_RH_THUMB        	1\n");
				wprintf_s(L"  WINBIO_ANSI_381_POS_RH_INDEX_FINGER 	2\n");
				wprintf_s(L"  WINBIO_ANSI_381_POS_RH_MIDDLE_FINGER	3\n");
				wprintf_s(L"  WINBIO_ANSI_381_POS_RH_RING_FINGER  	4\n");
				wprintf_s(L"  WINBIO_ANSI_381_POS_RH_LITTLE_FINGER	5\n");
				wprintf_s(L"  WINBIO_ANSI_381_POS_LH_THUMB        	6\n");
				wprintf_s(L"  WWINBIO_ANSI_381_POS_LH_INDEX_FINGER 	7\n");
				wprintf_s(L"  WINBIO_ANSI_381_POS_LH_MIDDLE_FINGER	8\n");
				wprintf_s(L"  WINBIO_ANSI_381_POS_LH_RING_FINGER  	9\n");
				wprintf_s(L"  WINBIO_ANSI_381_POS_LH_LITTLE_FINGER	10\n");
				std::cin >> nSelect;

VerifyAgain:
				//subFactor = WINBIO_ANSI_381_POS_RH_THUMB;
				subFactor = (WINBIO_BIOMETRIC_SUBTYPE)nSelect;
				hr = Verify(subFactor);
				//hr = VerifyWithCallback(FALSE, subFactor);
				if (hr == WINBIO_E_BAD_CAPTURE)
				{
					verifyCounter++;
					if (verifyCounter == 3)
						break;
					goto VerifyAgain;
				}
				break;

				//Identify
			case 'c':
				Identify();
				//hr = IdentifyWithCallback(FALSE)
				break;

				//CaptureSample
			case 'd':
				CaptureSample();
				//hr = CaptureSampleWithCallback(FALSE);
				break;

			case 'e':
				EnumerateSensors();
				break;

			case 'f':
				LocateSensor();
				//hr = LocateSensorWithCallback(FALSE);
				break;

			case 'g':
				EnumEnrollments();
				break;

			case 'h':
				EnumDatabases();
				break;

			case 'i':
				EnumSvcProviders();
				break;

			case 'j':
				DeleteTemplate();
				break;

			case 'k':
				EnumEnrollments(g_subFactorArray, &g_subFactorCount);
				wprintf_s(L" g_subFactorCount = %d\n", g_subFactorCount);
				for (SIZE_T index = 0; index < g_subFactorCount; ++index)
					wprintf_s(L" g_subFactorArray[%d] = %d\n", index, g_subFactorArray[index]);
				break;

			case 'q':
				wprintf_s(L"Bye ~~\n");
				g_bLoop = FALSE;
				break;

			default:
				wprintf_s(L"Type Error!!! Please Check Your Enter ~~\n");
				wprintf_s(L"\n");
				break;
		}
	}
	
	//GetCredentialState();

	//WinbioAsyncLocateSensor();

	//EnumerateSensors();
	
	//LocateSensor();
	//LocateSensorWithCallback(FALSE);
	
	//EnumEnrollments();

	//Enroll
	//WINBIO_BIOMETRIC_SUBTYPE subFactor = 0x02;
	//EnrollSysPool(FALSE, subFactor);
	//EnrollSysPoolWithCallback(FALSE, FALSE, WINBIO_ANSI_381_POS_RH_INDEX_FINGER);
	
	//Identify
	//Identify();
	//IdentifyWithCallback(FALSE);
	
	//Verify
	//WINBIO_BIOMETRIC_SUBTYPE subFactor = 0x01;
	//Verify(subFactor);
	//VerifyWithCallback(FALSE, subFactor);

	//CaptureSample();
	//CaptureSampleWithCallback(FALSE);

	//EnumDatabases();
	//EnumSvcProviders();

	//RemoveCredential();
	system("pause");
	return 0;
}
