#include <iostream>
#include <format>
#include <filesystem>
#include <stdexcept>
#include <string_view>

#include <Windows.h>
#include <Psapi.h>

#include <ArgParser/ArgParser.hpp>

//========================================

bool QUIET = false;

//========================================

void Inject(HANDLE process, std::string_view dll_path);

//========================================

int main(int argc, char* argv[])
{
	try
	{
		ArgParser args {
	 		{"help",   "Print usage reference and exit"    },
	 		{"name",   "Identify process by name substring"},
	 		{"create", "Create process injected"           },
			{"quiet",  "Suppress output"                   }
		};
	 
		args.parse(argc, argv);
		if (args["help"] || args.getArgumentCount() < 2)
		{
			std::cout << std::format(
				"Usage: {0}    [OPTIONS] <PID>  <DLL> - inject DLL into an existing process by PID \n"
				"       {0} -n [OPTIONS] <NAME> <DLL> - inject DLL into an existing process by name\n"
				"       {0} -c [OPTIONS] <EXE>  <DLL> - create process with DLL injected           \n"
				"                                                                                  \n"
				"Available options:                                                                \n",
				args.getExecutablePath().filename().string()
			);

			std::cout << args << std::endl;
		}

		QUIET = args["quiet"];

		std::filesystem::path dll_path = args[1];

		HANDLE process = reinterpret_cast<HANDLE>(args[0].as<unsigned long long>());
		Inject(process, dll_path.string());
	}
	
	catch (std::exception exc)
	{
		std::cerr << exc.what() << std::endl;
	}
}

//========================================

void Inject(HANDLE process, std::string_view dll_path)
{
	auto* remote_dll_path = reinterpret_cast<char*>(
		VirtualAllocEx(
			process,
			nullptr,
			dll_path.length() + 1,
			MEM_COMMIT,
			PAGE_READWRITE
		)
	);

	if (!remote_dll_path)
		throw std::runtime_error("Unable to remotely allocate memory in target process");

	if (!WriteProcessMemory(
		process,
		remote_dll_path,
		dll_path.data(),
		dll_path.length(),
		nullptr
	))
		throw std::runtime_error("Unable to write dll path into target process memory");

	char trailing_null = '\0';
	if (!WriteProcessMemory(
		process,
		remote_dll_path + dll_path.length(),
		&trailing_null,
		sizeof(trailing_null),
		nullptr
	))
		throw std::runtime_error("Unable to write trailing null into target process memory");

	auto remote_thread = CreateRemoteThread(
		process,
		nullptr,
		0,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA),
		remote_dll_path,
		0,
		nullptr
	);

	if (!remote_thread)
		throw std::runtime_error("Unable to start remote thread");

	WaitForSingleObject(remote_thread, INFINITE);

	if (!QUIET)
	{
		char process_name[MAX_PATH] = "";
		GetModuleBaseNameA(process, 0, process_name, std::size(process_name));

		std::cout 
			<< dll_path << " was successfully injected into " << process_name << std::endl;
	}
}

//========================================