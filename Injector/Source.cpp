#include <Windows.h>
#include <Psapi.h>
#include <cstdio>
#include <filesystem>

#pragma warning(disable: 6387)

//----------------------------------------------

constexpr size_t BUFFSIZE = 1024;

//----------------------------------------------

const char* GetLastErrorMessage();

//----------------------------------------------

int main(int argc, char* argv[])
{
	if (argc < 3)
	{
		printf("Usage: inject.exe <target process id> <injected dll path>");
		return 0;
	}

	for (const char* ch = argv[1]; *ch; ch++)
	{
		if (!isdigit(*ch))
		{
			fprintf(stderr, "invalid process id\n");
			return 1;
		}
	}

	int pid = strtoul(argv[1], nullptr, 10);

	std::filesystem::path dll_path = std::filesystem::absolute(argv[2]);
	std::string dll_path_string = dll_path.string();

	if (!std::filesystem::exists(dll_path))
	{
		fprintf(stderr, "File '%s' does not exist\n", dll_path_string.c_str());
		return 1;
	}

	HANDLE target_process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (!target_process_handle)
	{
		fprintf(stderr, "Unable to open process with id %lu: %s\n", pid, GetLastErrorMessage());
		return 1;
	}

	void* remote_module_path_addr = VirtualAllocEx(
		target_process_handle, 
		nullptr, 
		dll_path_string.length()+1, 
		MEM_COMMIT, 
		PAGE_READWRITE
	);

	if (!remote_module_path_addr)
	{
		CloseHandle(target_process_handle);
		fprintf(stderr, "Unable to allocate memory for dll path buffer in target process: %s\n", GetLastErrorMessage());
		return 1;
	}

	size_t bytes_written = 0;
	if (!WriteProcessMemory(
		target_process_handle, 
		remote_module_path_addr, 
		dll_path_string.c_str(), 
		dll_path_string.length()+1, 
		&bytes_written
	))
	{
		VirtualFreeEx(target_process_handle, remote_module_path_addr, 0, MEM_RELEASE);
		CloseHandle(target_process_handle);
		fprintf(stderr, "Unable to write dll path into target process memory space: %s\n", GetLastErrorMessage());
		return 1;
	}

	auto remote_thread_procedure = reinterpret_cast<LPTHREAD_START_ROUTINE>
	(
		GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA")
	);

	HANDLE remote_thread = CreateRemoteThread(
		target_process_handle, 
		nullptr, 
		0, 
		remote_thread_procedure,
		remote_module_path_addr,
		0,
		nullptr
	);

	if (!remote_thread)
	{
		VirtualFreeEx(target_process_handle, remote_module_path_addr, 0, MEM_RELEASE);
		CloseHandle(target_process_handle);
		fprintf(stderr, "Unable to start thread inside target process: %s\n", GetLastErrorMessage());
		return 1;
	}

	WaitForSingleObject(remote_thread, INFINITE);

	char process_base_name[BUFFSIZE] = "";
	GetModuleBaseNameA(target_process_handle, 0, process_base_name, BUFFSIZE);
	printf("%s was successfully injected into %s.\n", dll_path.filename().string().c_str(), process_base_name);

	VirtualFreeEx(target_process_handle, remote_module_path_addr, 0, MEM_RELEASE);
	CloseHandle(target_process_handle);
}

//----------------------------------------------

const char* GetLastErrorMessage()
{
	static char message[BUFFSIZE] = "";
	FormatMessageA(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr,
		GetLastError(),
		MAKELANGID(LANG_SYSTEM_DEFAULT, SUBLANG_NEUTRAL),
		message,
		BUFFSIZE,
		nullptr
	);

	for (char* ch = message; *ch; ch++)
	{
		if (*ch == '\n') 
		{
			*ch = '\0';
			break;
		}
	}

	return message;
}

//----------------------------------------------