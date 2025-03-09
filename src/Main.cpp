#include <iostream>
#include <format>
#include <filesystem>
#include <stdexcept>
#include <string_view>

#include <Windows.h>
#include <Psapi.h>
#include <Shlwapi.h>

#include <ArgParser/ArgParser.hpp>

//========================================

class WinAPIError: public std::runtime_error
{
public:
	using std::runtime_error::runtime_error;

};

//========================================

class Main
{
public:
	Main() = default;
	~Main();

	void start(int argc, char* argv[]);

private:
	ArgParser m_args {
	 	{"help",   "Print usage reference and exit"    },
	 	{"name",   "Identify process by name substring"},
	 	{"create", "Create process injected"           },
		{"quiet",  "Suppress output"                   }
	};

	bool        m_quiet          = false;
	HANDLE      m_process_handle = nullptr;
	HANDLE      m_thread_handle  = nullptr;
	std::string m_dll_name       = "";

	void inject();

};

//========================================

HANDLE FindProcess(std::string_view substr);

//========================================

Main::~Main()
{
	if (m_thread_handle)
	{
		ResumeThread(m_thread_handle);
		CloseHandle(m_thread_handle);
	}

	if (m_process_handle)
		CloseHandle(m_process_handle);
}

void Main::start(int argc, char* argv[])
{
	try
	{
		m_args.parse(argc, argv);
		if (m_args["help"] || m_args.getArgumentCount() < 2)
		{
			std::cout << std::format(
				"Usage: {0}    [OPTIONS] <PID>  <DLL> - inject DLL into an existing process by PID \n"
				"       {0} -n [OPTIONS] <NAME> <DLL> - inject DLL into an existing process by name\n"
				"       {0} -c [OPTIONS] <EXE>  <DLL> - create process with DLL injected           \n"
				"                                                                                  \n"
				"Available options:                                                                \n",
				m_args.getExecutablePath().filename().string()
			);

			std::cout << m_args << std::endl;
			return;
		}

		m_quiet = m_args["quiet"];
		m_dll_name = m_args[1].as<std::string_view>();

		// Create child process
		if (m_args["create"])
		{
			std::string exe_path = m_args[0];

			std::string command_line = exe_path;
			for (const auto& argument: m_args.getRemainingArguments())
				(command_line += ' ') += argument;

			STARTUPINFOA        startup_info = {};
			PROCESS_INFORMATION process_info = {};

			if (
				!CreateProcessA(
					exe_path.c_str(),
					command_line.data(),
					NULL,
					NULL,
					false,
					CREATE_SUSPENDED,
					NULL,
					NULL,
					&startup_info,
					&process_info
				)
			)
				throw WinAPIError("Unable to create process");

			m_process_handle = process_info.hProcess;
			m_thread_handle  = process_info.hThread;

			inject();
		}

		// Find existing process
		else
		{
			m_process_handle = m_args["name"]
				? FindProcess(m_args[0])
				: OpenProcess(PROCESS_ALL_ACCESS, true, m_args[0]);

			if (!m_process_handle)
				throw std::runtime_error("Process not found");

			inject();
		}
	}

	catch (const WinAPIError& exc)
	{
		char* message = nullptr;
		FormatMessageA(
			FORMAT_MESSAGE_FROM_SYSTEM     | 
			FORMAT_MESSAGE_ALLOCATE_BUFFER | 
			FORMAT_MESSAGE_IGNORE_INSERTS,
			nullptr,
			GetLastError(),
			0,
			reinterpret_cast<char*>(&message),
			0,
			nullptr
		);

		std::cerr << exc.what() << ": " << message << std::endl;
		LocalFree(message);
	}

	catch (const std::exception& exc)
	{
		std::cerr << exc.what() << std::endl;
	}
}

void Main::inject()
{
	auto* remote_dll_path = reinterpret_cast<char*>(
		VirtualAllocEx(
			m_process_handle,
			nullptr,
			m_dll_name.length() + 1,
			MEM_COMMIT,
			PAGE_READWRITE
		)
	);

	if (!remote_dll_path)
		throw WinAPIError("Unable to remotely allocate memory in target process");

	if (!WriteProcessMemory(
		m_process_handle,
		remote_dll_path,
		m_dll_name.data(),
		m_dll_name.length() + 1,
		nullptr
	))
		throw WinAPIError("Unable to write dll path into target process memory");

	auto remote_thread = CreateRemoteThread(
		m_process_handle,
		nullptr,
		0,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA),
		remote_dll_path,
		0,
		nullptr
	);

	if (!remote_thread)
		throw WinAPIError("Unable to start remote thread");

	WaitForSingleObject(remote_thread, INFINITE);
	VirtualFreeEx(m_process_handle, remote_dll_path, 0, MEM_RELEASE);

	if (!m_quiet)
	{
		char process_name[MAX_PATH] = "";
		GetModuleBaseNameA(m_process_handle, 0, process_name, std::size(process_name));

		std::cout 
			<< m_dll_name 
			<< " was successfully injected into " << process_name 
			<< std::endl;
	}
}

//========================================

HANDLE FindProcess(std::string_view substr)
{
	DWORD process_ids[1024] = {};
	DWORD read_bytes = 0;
	EnumProcesses(process_ids, sizeof(process_ids), &read_bytes);

	for (size_t i = 0; i < read_bytes/sizeof(DWORD); i++)
	{
		HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, false, process_ids[i]);

		char buffer[MAX_PATH] = "";
		std::string_view process_name(
			buffer,
			GetModuleBaseNameA(process, 0, buffer, std::size(buffer))
		);
		
		if (
			std::search(
				process_name.begin(), 
				process_name.end(),
				substr.begin(), 
				substr.end(),
				[](char a, char b) -> bool
				{
					return std::tolower(a) == std::tolower(b);
				}
			) != process_name.end()
		)
			return process;

		CloseHandle(process);
	}

	return nullptr;
}

//========================================

int main(int argc, char* argv[])
{
	Main instance;
	instance.start(argc, argv);
}

//========================================