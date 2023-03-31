#pragma once
#include <Windows.h>
#include <string>

LPVOID MapFileIntoMemory(const std::string& exePath, size_t* fileSize = NULL);

class Executable
{
public:
	LPVOID fileBase;
	LPVOID imgBase;

	uint64_t EmulationImageBase;

	size_t fileSize;
	size_t imgSize;

	//Image headers
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS ntHeader;
	PIMAGE_FILE_HEADER fileHeader;
	PIMAGE_OPTIONAL_HEADER optionalHeader;

	uint64_t EmulationStart;
	uint64_t EmulationEnd;
	uint64_t IATHookBase;

	bool bInitialised;

	bool CheckMagicHeader();

	void AllocAndLoadSections(LPVOID fileBase);

	void ApplyRelocations();

	void HookImports(uint64_t newBase);

	bool LoadExecutable(const std::string& exePath);

	Executable(const std::string& path, uint64_t ImageBase = 0x0);

};

