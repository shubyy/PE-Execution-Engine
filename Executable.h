#pragma once
#include <Windows.h>
#include <string>

class Executable
{
public:
	LPVOID fileBase;
	LPVOID imgBase;

	size_t fileSize;
	size_t imgSize;

	//Image headers
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS ntHeader;
	PIMAGE_FILE_HEADER fileHeader;
	PIMAGE_OPTIONAL_HEADER optionalHeader;

	bool bInitialised;

	LPVOID MapFileIntoMemory(const std::string& exePath);

	bool CheckMagicHeader(PIMAGE_DOS_HEADER execHndle);

	void AllocAndLoadSections(LPVOID fileBase, PIMAGE_NT_HEADERS ntHeader);

	bool LoadExecutable(const std::string& exePath);

	Executable(const std::string& path);

};

