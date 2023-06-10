#pragma once

#include <Windows.h>
#include <memory>

//----------------------------------------------

template<typename T>
constexpr T RelativeVirtualAddress(HMODULE module, uintptr_t address)
{
	return reinterpret_cast<T>(reinterpret_cast<uintptr_t>(module) + address);
}

template <typename T>
T SetProcAddress(const char* target_module_name, const char* target_proc_name, T new_proc)
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
					T original_procedure = reinterpret_cast<T>(*function_import_record);

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