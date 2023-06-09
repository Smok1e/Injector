#include <Windows.h>
#include <Psapi.h>
#include <Shlwapi.h>

#include <cstdio>
#include <cstdarg>
#include <filesystem>

#pragma warning(disable: 6387)

//----------------------------------------------

constexpr size_t BUFFSIZE = 1024;

bool   Quiet               = false;
bool   DebugOutput         = false;
HANDLE RemoteProcessHandle = nullptr;
void*  RemoteDllPath       = nullptr;

//----------------------------------------------

bool        IsOption           (const char* arg);
bool        IsValidUnsigned    (const char* str);
char*       GetArgument        (int argc, char* argv[], size_t index);
unsigned    GetArgumentUnsigned(int argc, char* argv[], size_t index);
bool        IsOptionPresent    (int argc, char* argv[], char option);
		    
void        PrintUsage         ();
void        InjectDLL          (HANDLE process, const std::filesystem::path& dll_path);
void        Cleanup            ();

void        DebugPrintf        (const char* format, ...);
void        ExitWithError      (const char* format, ...);

HANDLE      FindProcess        (const char* substring);
const char* GetLastErrorMessage();

//----------------------------------------------

int main(int argc, char* argv[])
{
	atexit(Cleanup);

	if (IsOptionPresent(argc, argv, 'h'))
	{
		PrintUsage();
		return 0;
	}

	Quiet       = IsOptionPresent(argc, argv, 'q');
	DebugOutput = IsOptionPresent(argc, argv, 'v');

	RemoteProcessHandle = IsOptionPresent(argc, argv, 'n')
		? FindProcess(GetArgument(argc, argv, 0))
		: reinterpret_cast<HANDLE>(GetArgumentUnsigned(argc, argv, 0));

	if (!RemoteProcessHandle)
		ExitWithError("Process not found\n");

	std::filesystem::path dll_path = std::filesystem::absolute(GetArgument(argc, argv, 1));
	InjectDLL(RemoteProcessHandle, dll_path.string());
	
	return 0;
}

//----------------------------------------------

bool IsOption(const char* arg)
{
	return *arg == '-';
}

bool IsValidUnsigned(const char* str)
{
	for (const char* ch = str; *ch; ch++)
		if (!isdigit(*ch)) return false;

	return true;
}

char* GetArgument(int argc, char* argv[], size_t index)
{
	for (size_t i = 1, arg = 0; i < argc; i++, arg += !IsOption(argv[i]))
		if (arg == index+1) return argv[i];

	ExitWithError("Expected at least %zu arguments\n", index+1);
	return nullptr;
}

unsigned GetArgumentUnsigned(int argc, char* argv[], size_t index)
{
	char* arg = GetArgument(argc, argv, index);
	if (!IsValidUnsigned(arg))
	{
		ExitWithError("Argument #%zu is not a valid unsigned number\n", index+1);
		return 0;
	}

	return strtoul(arg, nullptr, 10);
}

bool IsOptionPresent(int argc, char* argv[], char option)
{
	for (size_t i = 0; i < argc; i++)
	{
		if (!IsOption(argv[i]))
			continue;

		for (const char* ch = argv[i]+1; *ch; ch++)
			if (*ch == option) return true;
	}

	return false;
}

//----------------------------------------------

void PrintUsage()
{
	printf("Usage: inject.exe -[hnvq] <target process id> <injected dll path>\n");
	printf("  -h: Print help\n");
	printf("  -n: Target process is process name substring\n");
	printf("  -v: Verbous mode\n");
	printf("  -q: Quiet mode\n");
}

void InjectDLL(HANDLE process, const std::filesystem::path& dll_path)
{
	std::string dll_path_string = dll_path.string();
	if (!std::filesystem::exists(dll_path))
		ExitWithError("File '%s' does not exist\n", dll_path_string.c_str());

	size_t remote_dll_path_size = dll_path_string.length()+1;
	DebugPrintf("Allocating %zu bytes of memory in remote process to store dll path\n", remote_dll_path_size);

	if (!(RemoteDllPath = VirtualAllocEx(
		process,
		nullptr,
		dll_path_string.length()+1,
		MEM_COMMIT,
		PAGE_READWRITE
	))) ExitWithError("Unable to allocate memory for dll path buffer in target process: %s\n", GetLastErrorMessage());

	DebugPrintf("Writing memory...\n");

	size_t written_bytes = 0;
	if (!WriteProcessMemory(
		process,
		RemoteDllPath,
		dll_path_string.c_str(),
		dll_path_string.length()+1,
		&written_bytes
	)) ExitWithError("Unable to write dll path into target process memory space: %s\n", GetLastErrorMessage());

	DebugPrintf("Written %zu bytes\n", written_bytes);

	auto thread_proc = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");

	DebugPrintf("Starting remote thread\n");
	HANDLE thread = CreateRemoteThread(
		process, 
		nullptr, 
		0, 
		reinterpret_cast<LPTHREAD_START_ROUTINE>(thread_proc),
		RemoteDllPath,
		0,
		nullptr
	);

	if (!thread)
		ExitWithError("Unable to start remote thread: %s\n", GetLastErrorMessage());

	DebugPrintf("Waiting for remote thread to terminate...\n");
	WaitForSingleObject(thread, INFINITE);
	DebugPrintf("Done\n");

	if (!Quiet)
	{
		char process_base_name[MAX_PATH] = "";
		GetModuleBaseNameA(process, 0, process_base_name, MAX_PATH);
		printf("%s was successfully injected into %s\n", dll_path.filename().string().c_str(), process_base_name);
	}
}

void Cleanup()
{
	DebugPrintf("Cleaning up...\n");
	if (RemoteProcessHandle) 
	{
		if (RemoteDllPath)
		{
			DebugPrintf("Releasing remote allocated memory...\n");
			VirtualFreeEx(RemoteProcessHandle, RemoteDllPath, 0, MEM_RELEASE);
		}

		DebugPrintf("Closing process handle...\n");
		CloseHandle(RemoteProcessHandle);
	}

	DebugPrintf("Done\n");
}

//----------------------------------------------

void DebugPrintf(const char* format, ...)
{
	if (DebugOutput)
	{
		printf("[DEBUG]: ");

		std::va_list args = {};
		va_start(args, format);
		vprintf(format, args);
		va_end(args);
	}
}

void ExitWithError(const char* format, ...)
{
	if (!Quiet)
	{
		std::va_list args = {};
		va_start(args, format);
		vfprintf(stderr, format, args);
		va_end(args);
	}

	exit(1);
}

//----------------------------------------------

HANDLE FindProcess(const char* substring)
{
	DebugPrintf("Searching process by substring '%s'...\n", substring);

	DWORD process_ids[BUFFSIZE] = {};
	DWORD read_bytes = 0;
	EnumProcesses(process_ids, sizeof(process_ids), &read_bytes);

	size_t process_count = read_bytes/sizeof(DWORD);
	for (size_t i = 0; i < process_count; i++)
	{
		HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, false, process_ids[i]);

		char process_base_name[BUFFSIZE] = "";
		GetModuleBaseNameA(process, 0, process_base_name, BUFFSIZE);
		if (StrStrIA(process_base_name, substring))
		{
			DebugPrintf("Found process '%s'\n", process_base_name);
			return process;
		}

		CloseHandle(process);
	}

	DebugPrintf("Specified process not found\n");
	return nullptr;
}

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