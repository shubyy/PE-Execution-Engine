#pragma once
#include <Windows.h>
#include <string>

#define MAX_IMPORT_NAME_LENGTH 128

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
	LPVOID fileBase;

	uint64_t EmulationImageBase;
	uint64_t PreferredImageBase;

	size_t fileSize;
	size_t imgSize;
	uint64_t EmulationStart;
	uint64_t EmulationEnd;
	uint64_t IATHookBase;

	bool bInitialised;

	virtual bool LoadExecutable();

	virtual void ApplyImportHooks(uint64_t);

	virtual void GetImportFromAddress(uint64_t address, char *moduleName, char* importName);

	Executable(LPVOID pFileBase, uint64_t size, uint64_t ImageBase = 0x0);

};