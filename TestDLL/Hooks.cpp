#include <Shlwapi.h>

#include "Hooks.h"
#include "Logging.h"

#include <filesystem>
#include <string>

//----------------------------------------------

HANDLE (*ORIGINAL_CreateFileA             )(LPCSTR,  DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = nullptr;
HANDLE (*ORIGINAL_CreateFileW             )(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = nullptr;
DWORD  (*ORIGINAL_GetPrivateProfileStringA)(LPCSTR, LPCSTR, LPCSTR, LPSTR, DWORD, LPCSTR)                       = nullptr;

//----------------------------------------------

HANDLE HOOK_CreateFileA(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
)
{
	if (StrStrIA(lpFileName, "algorithm"))
		DebugPrintf("CreateFileA called to open '%s'\n", lpFileName);

	return ORIGINAL_CreateFileA(
		lpFileName, 
		dwDesiredAccess, 
		dwShareMode, 
		lpSecurityAttributes, 
		dwCreationDisposition, 
		dwFlagsAndAttributes, 
		hTemplateFile
	);
}

HANDLE HOOK_CreateFileW(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
)
{
	// DebugPrintf(L"CreateFileW called to open '%s'\n", lpFileName);

	return ORIGINAL_CreateFileW(
		lpFileName, 
		dwDesiredAccess, 
		dwShareMode, 
		lpSecurityAttributes, 
		dwCreationDisposition, 
		dwFlagsAndAttributes, 
		hTemplateFile
	);
}

DWORD HOOK_GetPrivateProfileStringA(
	LPCSTR lpAppName,
	LPCSTR lpKeyName,
	LPCSTR lpDefault,
	LPSTR  lpReturnedString,
	DWORD  nSize,
	LPCSTR lpFileName
)
{
	DWORD result = ORIGINAL_GetPrivateProfileStringA(
		lpAppName,
		lpKeyName,
		lpDefault,
		lpReturnedString,
		nSize,
		lpFileName
	);

	DebugPrintf("GerPrivateProfileStringA(%s::%s::%s) => '%s'\n", lpFileName, lpAppName, lpKeyName, lpReturnedString);
	return result;
}

//----------------------------------------------