#pragma once
#include <Windows.h>
#include <string>

LPVOID MapFileIntoMemory(const std::string& exePath, size_t* fileSize = NULL);

enum EExecType
{
	ExecType_Unknown,
	ExecType_PE32,
	ExecType_PE64,
	ExecType_ELF,
	ExecType_PE64_KERNEL
};

class Executable
{
public:
	LPVOID imgBase;

	uint64_t EmulationImageBase;

	size_t fileSize;
	size_t imgSize;

	

	uint64_t EmulationStart;
	uint64_t EmulationEnd;
	uint64_t IATHookBase;

	bool bInitialised;

	bool CheckMagicHeader();

	void AllocAndLoadSections(LPVOID fileBase);

	void ApplyRelocations();

	void HookImports(uint64_t newBase);

	void LoadHeader(LPVOID fileBase);

	bool LoadExecutable(const std::string& exePath);

	Executable(const std::string& path, uint64_t ImageBase = 0x0);

};