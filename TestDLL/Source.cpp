#include <Windows.h>
#include <Psapi.h>

#include "Hack.hpp"
#include "Hooks.h"
#include "Logging.h"

//----------------------------------------------

template <typename T>
void Overwrite(const char* module_name, const char* proc_name, T* original_proc, T new_proc);

//----------------------------------------------

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
	switch (reason)
	{
		case DLL_PROCESS_ATTACH:
		{
			AllocConsole();
			system("cls");

			char basename[MAX_PATH] = "";
			GetModuleBaseNameA(GetCurrentProcess(), 0, basename, MAX_PATH);

			DebugPrintf("========================{ DLL was injected into %s }========================\n", basename);
			Overwrite("KERNEL32.DLL", "CreateFileA",              &ORIGINAL_CreateFileA,              HOOK_CreateFileA             );
			Overwrite("KERNEL32.DLL", "CreateFileW",              &ORIGINAL_CreateFileW,              HOOK_CreateFileW             );
			Overwrite("KERNEL32.DLL", "GetPrivateProfileStringA", &ORIGINAL_GetPrivateProfileStringA, HOOK_GetPrivateProfileStringA);
			break;
		}

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}

	return true;
}

//----------------------------------------------

template <typename T>
void Overwrite(const char* module_name, const char* proc_name, T* original_proc, T new_proc)
{
	DebugPrintf("Overwriting %s::%s... ", module_name, proc_name);
	if (*original_proc = SetProcAddress(module_name, proc_name, new_proc)) DebugPrintf("Success\n");
	else DebugPrintf("Fail\n");
}

//----------------------------------------------