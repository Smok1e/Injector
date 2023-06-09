#include <Windows.h>
#include <cstdio>
#include <chrono>
#include <thread>

//----------------------------------------------

int main()
{
	SetConsoleOutputCP(CP_UTF8);

	for (size_t i = 0; true; i++)
	{
		FILE* file = nullptr;
		errno_t err = fopen_s(&file, "C:\\Users\\smok1e\\Desktop\\file.txt", "rb");
		if (!file || err)
		{
			if (file)
				fclose(file);

			printf("Failed to open file\n");
			return 1;
		}

		char buffer[MAX_PATH] = "";
		size_t read_bytes = fread(buffer, 1, MAX_PATH, file);
		fclose(file);

		printf("[%zu]: %.*s\n", i, read_bytes, buffer);

		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}

//----------------------------------------------