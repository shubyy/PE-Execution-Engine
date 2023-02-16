#include "Executable.h"
#include <filesystem>
#include <iostream>

#include <fstream>

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

bool Executable::CheckMagicHeader(PIMAGE_DOS_HEADER execHndle)
{
    if (execHndle->e_magic == 0x5A4D)
        return true;

    return false;
}

void Executable::AllocAndLoadSections(LPVOID fileBase, PIMAGE_NT_HEADERS ntHeader)
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
        if (sectionHeader->SizeOfRawData > 0)
            std::memcpy(((BYTE*)imgBase) + sectionHeader->VirtualAddress, ((BYTE*)fileBase) + sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData);
}

bool Executable::LoadExecutable(const std::string& exePath)
{
    LPVOID fileBase = MapFileIntoMemory(exePath);
    if (!fileBase)
        return false;


    dosHeader = (PIMAGE_DOS_HEADER)fileBase;
    if (!CheckMagicHeader(dosHeader))
        return false;

    ntHeader = (PIMAGE_NT_HEADERS)(((BYTE*)fileBase) + dosHeader->e_lfanew);

    fileHeader = &ntHeader->FileHeader;
    optionalHeader = &ntHeader->OptionalHeader;

    AllocAndLoadSections(fileBase, ntHeader);
    if (!imgBase)
        return false;
}


Executable::Executable(const std::string& path)
{
    imgBase = NULL;
    fileBase = NULL;
    fileSize = 0;
    imgSize = 0;
    bInitialised = false;

    if (LoadExecutable(path))
        bInitialised = true;
}
