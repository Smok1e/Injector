# Injector
This is simple C++ windows program to inject DLL into an existing process, or to start a child process with DLL injected.

The purpose of such injection is to execute any code inside a process address space, which may be very useful for reverse engeneering or patching programs at runtime.

For example, this code, compiled into a DLL and injected into a process, will allow you to find out which files the program opens:
```c++
#include <iostream>
#include <format>
#include <Windows.h>
#include <Psapi.h>

// Relative virtual address
template<typename T>
constexpr T RVA(HMODULE module, uintptr_t offset)
{
	return reinterpret_cast<T>(reinterpret_cast<uintptr_t>(module) + offset);
}

// This hack will overwrite function address in process import table
template<typename T>
T SetProcAddress(const char* target_module_name, const char* target_prog_name, T new_procedure)
{
	auto module = GetModuleHandleA(nullptr);

	auto* dos_header = RVA<IMAGE_DOS_HEADER*>(module, 0);
	auto* nt_header  = RVA<IMAGE_NT_HEADERS*>(module, dos_header->e_lfanew);

	auto* import_entry = RVA<IMAGE_IMPORT_DESCRIPTOR*>(
		module, 
		nt_header -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
	);

	for (import_entry; import_entry->Name; import_entry++)
	{
		auto* module_name = RVA<const char*>(module, import_entry->Name);

		if (!_strcmpi(module_name, target_module_name))
		{
			auto* original_thunk = RVA<IMAGE_THUNK_DATA*>(module, import_entry->OriginalFirstThunk);
			auto* thunk          = RVA<IMAGE_THUNK_DATA*>(module, import_entry->FirstThunk        );

			for (original_thunk, thunk; original_thunk->u1.Function && thunk->u1.Function; original_thunk++, thunk++)
			{
				char* procedure_name = RVA<IMAGE_IMPORT_BY_NAME*>(
					module, 
					original_thunk->u1.AddressOfData
				)->Name;

				if (!strcmp(procedure_name, target_prog_name))
				{
					uintptr_t* procedure_import_record = reinterpret_cast<uintptr_t*>(&(thunk->u1.Function));
					T original_procedure = reinterpret_cast<T>(*procedure_import_record);

					DWORD record_page_protection = PAGE_READWRITE;
					VirtualProtect(
						procedure_import_record,
						sizeof(uintptr_t),
						record_page_protection,
						&record_page_protection
					);

					memcpy(procedure_import_record, &new_procedure, sizeof(uintptr_t));

					VirtualProtect(
						procedure_import_record,
						sizeof(uintptr_t),
						record_page_protection,
						&record_page_protection
					);

					return original_procedure;
				}
			}

			break;
		}
	}

	return nullptr;
}

// Here we'll store original CreateFileW imported from Kernel32.dll
HANDLE (*K32_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = nullptr;

// This function will replace CreateFileW import from Kernel32.dll
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
	std::wcout << "CreateFileW called: " << lpFileName << std::endl;
	return K32_CreateFileW(
		lpFileName, 
		dwDesiredAccess, 
		dwShareMode, 
		lpSecurityAttributes, 
		dwCreationDisposition, 
		dwFlagsAndAttributes, 
		hTemplateFile
	);
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
	switch (reason)
	{
		case DLL_PROCESS_ATTACH:
		{	
			//AttachConsole(ATTACH_PARENT_PROCESS);
			AllocConsole();

			FILE* dummy = nullptr;
			freopen_s(&dummy, "CONOUT$", "w", stdout);
			freopen_s(&dummy, "CONOUT$", "w", stderr);

			char basename[MAX_PATH] = "";
			GetModuleBaseNameA(GetCurrentProcess(), 0, basename, MAX_PATH);
			std::cout << "DLL is attached to " << basename << std::endl;

			if (K32_CreateFileW = SetProcAddress("KERNEL32.DLL", "CreateFileW", HOOK_CreateFileW))
				std::cout << "CreateFileW was successfully overwritten" << std::endl;

			else
				std::cout << "Unable to overwrite CreateFileW" << std::endl;
		}
	}

	return true;
}
```

# Building
```shell
git clone https://github.com/Smok1e/Injector
cd Injector
git submodule init && git submodule update
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

# Usage                                                    
inject.exe    [OPTIONS] <PID>  <DLL> - inject DLL into an existing process by PID
inject.exe -n [OPTIONS] <NAME> <DLL> - inject DLL into an existing process by name
inject.exe -c [OPTIONS] <EXE>  <DLL> - create process with DLL injected

Available options:
  -h, --help   - Print usage reference and exit
  -n, --name   - Identify process by name substring
  -c, --create - Create process injected
  -q, --quiet  - Suppress output
