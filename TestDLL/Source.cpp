#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <Psapi.h>
#include <cstdio>
#include <memory>
#include <cstdarg>

//----------------------------------------------

void* OverwriteImportProcAddress(const char* target_module_name, const char* target_proc_name, void* new_proc);

template<typename T>
constexpr T RelativeVirtualAddress(HMODULE module, uintptr_t address)
{
	return reinterpret_cast<T>(reinterpret_cast<uintptr_t>(module) + address);
}

void DebugPrintfV (const char*    format, va_list args);
void DebugPrintfWV(const wchar_t* format, va_list args);
void DebugPrintf  (const char*    format, ...);
void DebugPrintfW (const wchar_t* format, ...);

//----------------------------------------------

errno_t (*ORIGINAL_fopen_s)(FILE**, const char*, const char*) = nullptr;
errno_t HOOK_fopen_s(FILE** file, const char* filename, const char* mode)
{
	DebugPrintf("fopen_s called: %s, %s", filename, mode);
	return ORIGINAL_fopen_s(file, filename, mode);
}

FILE* (*ORIGINAL_fopen)(const char*, const char*) = nullptr;
FILE* HOOK_fopen(const char* filename, const char* mode)
{
	DebugPrintf("fopen called: %s, %s", filename, mode);
	return ORIGINAL_fopen(filename, mode);
}

HANDLE (*ORIGINAL_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = nullptr;
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
	DebugPrintf("CreateFileA called: %s", lpFileName);
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

HANDLE (*ORIGINAL_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = nullptr;
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
	DebugPrintfW(L"CreateFileW called: %s", lpFileName);
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

//----------------------------------------------

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
	switch (reason)
	{
		case DLL_PROCESS_ATTACH:
		{
			AllocConsole();

			char basename[MAX_PATH] = "";
			GetModuleBaseNameA(GetCurrentProcess(), 0, basename, MAX_PATH);
			DebugPrintf("DLL was injected into %s\n", basename);

			#define overwrite(type, proc)                                                                               \
			{																											\
				if (ORIGINAL_##proc = reinterpret_cast<type>(OverwriteImportProcAddress(nullptr, #proc, HOOK_##proc)))	\
					DebugPrintf("%s was overwritten\n", #proc);															\
																														\
				else 																									\
					DebugPrintf("%s not found\n", #proc);																\
			}

			overwrite(errno_t (*)(FILE**, const char*, const char*                                  ), fopen_s    );
			overwrite(FILE*   (*)(        const char*, const char*                                  ), fopen      );
			overwrite(HANDLE  (*)(LPCSTR,  DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE), CreateFileA);
			overwrite(HANDLE  (*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE), CreateFileW);

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

void* OverwriteImportProcAddress(const char* target_module_name, const char* target_proc_name, void* new_proc)
{
	HMODULE module = GetModuleHandleA(nullptr);
	auto* dos_header = RelativeVirtualAddress<IMAGE_DOS_HEADER*>(module, 0);
	auto* nt_header  = RelativeVirtualAddress<IMAGE_NT_HEADERS*>(module, dos_header->e_lfanew);

	auto* import_entry = RelativeVirtualAddress<IMAGE_IMPORT_DESCRIPTOR*>(
		module, 
		nt_header -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
	);

	for (import_entry; import_entry->Name; import_entry++)
	{
		auto* module_name = RelativeVirtualAddress<const char*>(module, import_entry->Name);

		if (!target_module_name || !_strcmpi(module_name, target_module_name))
		{
			auto* original_thunk = RelativeVirtualAddress<IMAGE_THUNK_DATA*>(module, import_entry->OriginalFirstThunk);
			auto* thunk          = RelativeVirtualAddress<IMAGE_THUNK_DATA*>(module, import_entry->FirstThunk        );

			for (original_thunk, thunk; original_thunk->u1.Function && thunk->u1.Function; original_thunk++, thunk++)
			{
				char* proc_name = RelativeVirtualAddress<IMAGE_IMPORT_BY_NAME*>(module, original_thunk->u1.AddressOfData)->Name;

				if (!target_proc_name || !_strcmpi(proc_name, target_proc_name))
				{
					uintptr_t* function_import_record = reinterpret_cast<uintptr_t*>(&(thunk -> u1.Function));
					void* original_procedure = reinterpret_cast<void*>(*function_import_record);

					DWORD record_page_protection = PAGE_READWRITE;
					if (!VirtualProtect(
						function_import_record, 
						sizeof(uintptr_t), 
						record_page_protection, 
						&record_page_protection
					)) return nullptr;

					std::memcpy(function_import_record, &new_proc, sizeof(uintptr_t));

					VirtualProtect(
						function_import_record, 
						sizeof(uintptr_t), 
						record_page_protection, 
						&record_page_protection
					);

					return original_procedure;
				}
			}			
		}
	}

	return nullptr;
}

//----------------------------------------------

void DebugPrintfV(const char* format, va_list args)
{
	std::va_list args_copy = {};
	va_copy(args_copy, args);

	size_t buffsize = vsnprintf(nullptr, 0, format, args) + 1;
	char* buffer = new char[buffsize];

	va_copy(args_copy, args);
	snprintf(buffer, buffsize, format, args);

	DWORD written = 0;
	WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), buffer, buffsize-1, &written, nullptr);
	delete[] buffer;
}

void DebugPrintfWV(const wchar_t* format, va_list args)
{
	std::va_list args_copy = {};
	va_copy(args_copy, args);

	size_t buffsize = _vsnwprintf(nullptr, 0, format, args) + 1;
	wchar_t* buffer = new wchar_t[buffsize];

	va_copy(args_copy, args);
	_vsnwprintf(buffer, buffsize, format, args);

	DWORD written = 0;
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), buffer, buffsize-1, &written, nullptr);	
	delete[] buffer;
}

void DebugPrintf(const char* format, ...)
{
	std::va_list args = {};
	va_start(args, format);
	DebugPrintfV(format, args);
	va_end(args);
}

void DebugPrintfW(const wchar_t* format, ...)
{
	std::va_list args = {};
	va_start(args, format);
	DebugPrintfWV(format, args);
	va_end(args);	
}

//----------------------------------------------