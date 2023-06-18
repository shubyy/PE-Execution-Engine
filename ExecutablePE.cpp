#include "ExecutablePE.h"
#include <iostream>
#include <iomanip>

#define RELOCFLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOCFLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

/*
bool ExecutablePE32::LoadExecutable()
{
    //Test file types
    pDosHeader = (PIMAGE_DOS_HEADER)fileBase;
    if (!CheckHeader(fileBase))
        return false;

    pNTHeader = (PIMAGE_NT_HEADERS32)(((BYTE*)fileBase) + pDosHeader->e_lfanew);

    pFileHeader = &pNTHeader->FileHeader;
    pOptionalHeader = &pNTHeader->OptionalHeader;
    imgSize = pOptionalHeader->SizeOfImage;
    EmulationStart = (uint64_t)EmulationImageBase + pOptionalHeader->AddressOfEntryPoint;
    PreferredImageBase = pOptionalHeader->ImageBase;
    if (!EmulationImageBase)
        EmulationImageBase = PreferredImageBase;

    IMAGE_SECTION_HEADER* firstHeader = IMAGE_FIRST_SECTION(pNTHeader);
    AllocAndLoadSections(firstHeader, fileBase);
    if (!imgBase)
        return false;

    return true;
}
*/

bool ExecutablePE::LoadExecutable()
{
    //Test file types
    pDosHeader = (PIMAGE_DOS_HEADER)fileBase;
    if (!CheckHeader(fileBase))
        return false;

    pNTHeader = (PIMAGE_NT_HEADERS)(((BYTE*)fileBase) + pDosHeader->e_lfanew);

    pFileHeader = &pNTHeader->FileHeader;
    pOptionalHeader = &pNTHeader->OptionalHeader;
    imgSize = pOptionalHeader->SizeOfImage;
    EmulationStart = (uint64_t)EmulationImageBase + pOptionalHeader->AddressOfEntryPoint;
    PreferredImageBase = pOptionalHeader->ImageBase;
    if (!EmulationImageBase)
        EmulationImageBase = PreferredImageBase;

    IMAGE_SECTION_HEADER* firstHeader = IMAGE_FIRST_SECTION(pNTHeader);
    AllocAndLoadSections(firstHeader, fileBase);
    if (!imgBase)
        return false;

    bInitialised = true;
    return true;
}

bool ExecutablePE::DumpExecutable(const std::string& path)
{
    void* dumpBase = VirtualAlloc(NULL,
        imgSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (!dumpBase)
        return false;

    CopyMemory(dumpBase, imgBase, imgSize);

    PIMAGE_DOS_HEADER dDosHeader = (PIMAGE_DOS_HEADER)dumpBase;
    PIMAGE_NT_HEADERS dNTHeader = (PIMAGE_NT_HEADERS)(((BYTE*)dumpBase) + dDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER dFileHeader = &dNTHeader->FileHeader;
    PIMAGE_SECTION_HEADER firstSection = IMAGE_FIRST_SECTION(dNTHeader);
    IMAGE_SECTION_HEADER* sectionHeader = firstSection;
    for (int i = 0; i != dFileHeader->NumberOfSections; i++, sectionHeader++)
    {
        DWORD size = 0;
        if(i == (dFileHeader->NumberOfSections - 1))
			size = imgSize - sectionHeader->VirtualAddress;
		else
			size = (sectionHeader + 1)->VirtualAddress - sectionHeader->VirtualAddress;


        size_t raw_size = sectionHeader->SizeOfRawData;
        std::cout << "Remapping Section file offset: " << std::setw(8) << sectionHeader->Name << std::setw(4) << " from: 0x" << (LPVOID)sectionHeader->PointerToRawData << " To: 0x" << (LPVOID)sectionHeader->VirtualAddress << " Size: 0x" << (LPVOID) << std::endl;

        sectionHeader->PointerToRawData = sectionHeader->VirtualAddress;
    }

    HANDLE newFile = CreateFileA(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD bytesWritten = 0;
    WriteFile(newFile, dumpBase, imgSize, &bytesWritten, NULL);
    CloseHandle(newFile);

    if (bytesWritten != imgSize)
        return false;

    return true;
}

void ExecutablePE::LoadHeader(LPVOID fileBase)
{
    uint32_t sizeOfheaders = pOptionalHeader->SizeOfHeaders;
    std::memcpy(imgBase, fileBase, sizeOfheaders);
}

void ExecutablePE::AllocAndLoadSections(IMAGE_SECTION_HEADER* firstSection, LPVOID fileBase)
{
    allocationSize = roundUp(imgSize, 4096);
    imgBase = VirtualAlloc(NULL,
        allocationSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (!imgBase)
        return;

    LoadHeader(fileBase);

    IMAGE_SECTION_HEADER* sectionHeader = firstSection;
    for (int i = 0; i != pFileHeader->NumberOfSections; i++, sectionHeader++)
    {
        if (sectionHeader->SizeOfRawData > 0)
        {
            BYTE* virtual_address = (BYTE*)imgBase + sectionHeader->VirtualAddress;
            size_t raw_size = sectionHeader->SizeOfRawData;
            std::cout << "Mapping Section: " << std::setw(8) << sectionHeader->Name << std::setw(4) << " at: 0x" << (LPVOID)virtual_address << " Size: 0x" << raw_size << std::endl;
            std::memcpy(virtual_address, ((BYTE*)fileBase) + sectionHeader->PointerToRawData, raw_size);
        }
    }

    //Apply relocations
    ApplyRelocations();
}

void ExecutablePE::ApplyImportHooks(uint64_t base)
{
    IMAGE_DATA_DIRECTORY *importDir = GetDataDirectoryFromIndex(IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importDir->Size)
    {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)imgBase + importDir->VirtualAddress);
        PIMAGE_IMPORT_DESCRIPTOR startImportDesc = importDesc;
        while (importDesc->Name)
        {
            ULONG_PTR* OFT = (ULONG_PTR*)((BYTE*)imgBase + importDesc->OriginalFirstThunk);
            ULONG_PTR* FT = (ULONG_PTR*)((BYTE*)imgBase + importDesc->FirstThunk);

            if (!OFT)
                OFT = FT;

            for (; *OFT; ++OFT, ++FT)
            {
                uint64_t reloc = base + ((uint64_t)OFT - (uint64_t)startImportDesc);
                *FT = (ULONG)reloc;
            }

            ++importDesc;
        }
        IATHookBase = base;
    }
    
}

bool ExecutablePE::CheckHeader(LPVOID fileBase)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(((BYTE*)fileBase) + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
		return false;

	return true;
}

void ExecutablePE::ApplyRelocations()
{
    uint64_t offset = EmulationImageBase - PreferredImageBase;
    if (offset)
    {
        if (GetDataDirectoryFromIndex(IMAGE_DIRECTORY_ENTRY_BASERELOC)->Size >= 0)
        {
            PIMAGE_BASE_RELOCATION relocInfo = (PIMAGE_BASE_RELOCATION)((BYTE*)imgBase + GetDataDirectoryFromIndex(IMAGE_DIRECTORY_ENTRY_BASERELOC)->VirtualAddress);
            while (relocInfo->VirtualAddress)
            {
                uint32_t entryCount = (relocInfo->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* reloc = (WORD*)(relocInfo + 1);
                for (uint32_t i = 0; i < entryCount; i++, reloc++)
                {
                    if (RELOCFLAG32(*reloc))
                    {
                        uint64_t* relocAddress = (uint64_t*)((BYTE*)imgBase + relocInfo->VirtualAddress + ((*reloc) & 0xFFF));
                        *relocAddress += offset;
                    }
                }
                relocInfo = (PIMAGE_BASE_RELOCATION)((BYTE*)relocInfo + relocInfo->SizeOfBlock);
            }
        }
    }
}

void ExecutablePE::GetImportFromAddress(uint64_t address, PIMAGE_IMPORT_DESCRIPTOR* module, PIMAGE_IMPORT_BY_NAME* import)
{
    //Calculate hook function from address
    uint64_t funcHookOffset = address - IATHookBase;

    if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
    {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)imgBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        uint64_t startImportDesc = (uint64_t)importDesc;
        while (importDesc->Name)
        {
            ULONG_PTR* OFT = (ULONG_PTR*)((BYTE*)imgBase + importDesc->OriginalFirstThunk);
            ULONG_PTR* FT = (ULONG_PTR*)((BYTE*)imgBase + importDesc->FirstThunk);

            if (!OFT)
                OFT = FT;

            for (; *OFT; ++OFT, ++FT)
            {
                uint64_t funcIATOffset = (uint64_t)OFT - (uint64_t)startImportDesc;
                if (funcIATOffset == funcHookOffset)
                {
                    //Function Match
                    PIMAGE_IMPORT_BY_NAME IATImport = (PIMAGE_IMPORT_BY_NAME)((BYTE*)imgBase + *OFT);
                    *import = IATImport;
                    *module = importDesc;
                    return;
                }
            }
            ++importDesc;
        }
    }
}

IMAGE_DATA_DIRECTORY* ExecutablePE::GetDataDirectoryFromIndex(uint32_t index)
{
    if(index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
		return nullptr;

    return &pOptionalHeader->DataDirectory[index];
}

/*
IMAGE_DATA_DIRECTORY* ExecutablePE32::GetDataDirectoryFromIndex(uint32_t index)
{
    if (index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        return nullptr;

    return &pOptionalHeader->DataDirectory[index];
}
*/

bool ExecutablePE::IsValid(LPVOID fileBase)
{
    if (!CheckHeader(fileBase))
        return false;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)fileBase;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(((BYTE*)fileBase) + pDosHeader->e_lfanew);
    if (ntHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return false;

    return true;
}

/*
bool ExecutablePE32::IsValid(LPVOID fileBase)
{
    if (!CheckHeader(fileBase))
		return false;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)fileBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(((BYTE*)fileBase) + pDosHeader->e_lfanew);

	if (ntHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
		return false;

	return true;
}
*/
