#pragma once

#include <cstdio>
#include <cstdarg>

//----------------------------------------------

void DebugPrintfV(const char*    format, va_list args);
void DebugPrintfV(const wchar_t* format, va_list args);
void DebugPrintf (const char*    format, ...);
void DebugPrintf (const wchar_t* format, ...);

#define DebugPrintfL(format, ...)                                 \
	DebugPrintf("[line #%d, function %s]: ", __LINE__, __func__); \
	DebugPrintf(format, __VA_ARGS__);

//----------------------------------------------