#include "Executable.h"
#include <filesystem>
#include <iostream>

#include <fstream>

#define RELOCFLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOCFLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

LPVOID Executable::MapFileIntoMemory(const std::string& exePath)
{
    std::ifstream exeFile(exePath, std::ios::binary | std::ios::in);
    if (!exeFile)
        return NULL;

    fileSize = std::filesystem::file_size(exePath);
    if (fileSize < 0x100)
        return NULL;

    void* exeData = malloc(fileSize);

    exeFile.read((char*)exeData, fileSize);
    return exeData;
}

bool Executable::CheckMagicHeader()
{
    if (dosHeader->e_magic == 0x5A4D)
        return true;

    return false;
}

void Executable::AllocAndLoadSections(LPVOID fileBase)
{
    imgSize = optionalHeader->SizeOfImage;
    imgBase = VirtualAlloc((LPVOID)optionalHeader->ImageBase,
        imgSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (!imgBase)
        return;
    
    IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
    for (int i = 0; i != fileHeader->NumberOfSections; i++, sectionHeader++)
    {
        if (sectionHeader->SizeOfRawData > 0)
        {
            BYTE* virtual_address = (BYTE*)imgBase + sectionHeader->VirtualAddress;
            size_t raw_size = sectionHeader->SizeOfRawData;
            std::cout  << "Mapping Section: " << std::setw(8) << sectionHeader->Name << std::setw(4) << " at: 0x" << (LPVOID) virtual_address << " Size: 0x" << raw_size << std::endl;
            std::memcpy(virtual_address, ((BYTE*)fileBase) + sectionHeader->PointerToRawData, raw_size);
        }
    }
       
    //Apply relocations
    
        ApplyRelocations();
            
}

void Executable::ApplyRelocations()
{
    uint64_t offset = EmulationImageBase - (uint64_t)optionalHeader->ImageBase;
    if (offset)
    {
        if (optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size >= 0)
        {
            PIMAGE_BASE_RELOCATION relocInfo = (PIMAGE_BASE_RELOCATION)((BYTE*)imgBase + optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            while (relocInfo->VirtualAddress)
            {
                uint32_t entryCount = (relocInfo->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* reloc = (WORD*)(relocInfo + 1);
                for (int i = 0; i < entryCount; i++, reloc++)
                {
                    if (RELOCFLAG64(*reloc))
                    {
                        uint64_t* relocAddress = (uint64_t*) ((BYTE*)imgBase + relocInfo->VirtualAddress + ((*reloc) & 0xFFF));
                        *relocAddress += offset;
                    }
                }
                relocInfo = (PIMAGE_BASE_RELOCATION) ((BYTE*) relocInfo + relocInfo->SizeOfBlock);
            }
        }
    }
    
}

bool Executable::LoadExecutable(const std::string& exePath)
{
    LPVOID fileBase = MapFileIntoMemory(exePath);
    if (!fileBase)
        return false;

    dosHeader = (PIMAGE_DOS_HEADER)fileBase;
    if (!CheckMagicHeader())
        return false;

    ntHeader = (PIMAGE_NT_HEADERS)(((BYTE*)fileBase) + dosHeader->e_lfanew);

    fileHeader = &ntHeader->FileHeader;
    optionalHeader = &ntHeader->OptionalHeader;

    EmulationStart = (uint64_t)EmulationImageBase + optionalHeader->AddressOfEntryPoint;

    AllocAndLoadSections(fileBase);
    if (!imgBase)
        return false;

    return true;
}


Executable::Executable(const std::string& path, uint64_t ImageBase)
{
    imgBase = NULL;
    fileBase = NULL;
    fileSize = 0;
    imgSize = 0;
    EmulationImageBase = ImageBase;
    bInitialised = false;

    if (LoadExecutable(path))
        bInitialised = true;
}
