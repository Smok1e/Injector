#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include "Logging.h"

//----------------------------------------------

void DebugPrintfV(const char* format, va_list args)
{
	std::va_list args_copy = {};
	va_copy(args_copy, args);

	size_t buffsize = vsnprintf(nullptr, 0, format, args_copy) + 1;
	char* buffer = new char[buffsize];

	vsnprintf(buffer, buffsize, format, args);

	DWORD written = 0;
	WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), buffer, buffsize-1, &written, nullptr);
	delete[] buffer;
}

void DebugPrintfV(const wchar_t* format, va_list args)
{
	std::va_list args_copy = {};
	va_copy(args_copy, args);

	size_t buffsize = _vsnwprintf(nullptr, 0, format, args_copy) + 1;
	wchar_t* buffer = new wchar_t[buffsize];
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

void DebugPrintf(const wchar_t* format, ...)
{
	std::va_list args = {};
	va_start(args, format);
	DebugPrintfV(format, args);
	va_end(args);	
}

//----------------------------------------------