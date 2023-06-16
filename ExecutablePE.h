#pragma once
#include "Executable.h"

class ExecutablePE : public Executable
{
protected:
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_FILE_HEADER pFileHeader;
	virtual void AllocAndLoadSections(IMAGE_SECTION_HEADER*, LPVOID);
	PIMAGE_NT_HEADERS64 pNTHeader;
	PIMAGE_OPTIONAL_HEADER64 pOptionalHeader;
private:
	void ApplyRelocations();
	void ApplyImportHooks(uint64_t) override;
public:
	using Executable::Executable;
	static bool CheckHeader(LPVOID fileBase);
	void LoadHeader(LPVOID fileBase);
	void GetImportFromAddress(uint64_t address, PIMAGE_IMPORT_DESCRIPTOR* module, PIMAGE_IMPORT_BY_NAME* import);
	virtual IMAGE_DATA_DIRECTORY* GetDataDirectoryFromIndex(uint32_t);
	bool LoadExecutable() override;
	static bool IsValid(LPVOID fileBase);
};

