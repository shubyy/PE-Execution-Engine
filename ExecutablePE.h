#pragma once
#include "Executable.h"


class ExecutablePE : public Executable
{
	using Executable::Executable;
protected:
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_FILE_HEADER pFileHeader;
private:
	
	virtual void LoadHeader(LPVOID fileBase);
	virtual void AllocAndLoadSections(IMAGE_SECTION_HEADER*, LPVOID );
	void ApplyRelocations();
	void ApplyImportHooks(uint64_t) override;
public:
	static bool CheckHeader(LPVOID fileBase);
	void GetImportFromAddress(uint64_t address, char* moduleName, char* importName) override;
	virtual IMAGE_DATA_DIRECTORY* GetDataDirectoryFromIndex(uint32_t);
	
};

class ExecutablePE32 : public ExecutablePE
{
	using ExecutablePE::ExecutablePE;
	PIMAGE_NT_HEADERS32 pNTHeader;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader;
	bool LoadExecutable() override;
	void LoadHeader(LPVOID fileBase) override;
	IMAGE_DATA_DIRECTORY* GetDataDirectoryFromIndex(uint32_t) override;
public:
	static bool IsValid(LPVOID fileBase);
};

class ExecutablePE64 : public ExecutablePE
{
	using ExecutablePE::ExecutablePE;
	PIMAGE_NT_HEADERS64 pNTHeader;
	PIMAGE_OPTIONAL_HEADER64 pOptionalHeader;

	bool LoadExecutable() override;
	void LoadHeader(LPVOID fileBase) override;
	IMAGE_DATA_DIRECTORY* GetDataDirectoryFromIndex(uint32_t) override;
public:
	static bool IsValid(LPVOID fileBase);
};

