#include <Windows.h>
#include <Psapi.h>
#include <cstdio>

//----------------------------------------------

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
	switch (reason)
	{
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		{
			char current_process_name[MAX_PATH] = "";
			GetModuleBaseNameA(GetCurrentProcess(), 0, current_process_name, MAX_PATH);
			printf("Current process name: %s\n", current_process_name);

			break;
		}

		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}

	return true;
}

//----------------------------------------------