#include "Executable.h"
#include <filesystem>
#include <iostream>
#include <fstream>

#define RELOCFLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOCFLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

Executable::Executable(LPVOID pFileBase, uint64_t size, uint64_t ImageBase)
{
    imgBase = NULL;
    fileBase = pFileBase;
    fileSize = size;
    imgSize = 0;
    IATHookBase = 0;
    EmulationImageBase = ImageBase;
    bInitialised = false;
    PreferredImageBase = 0x0;
}

uint64_t Executable::convertFromPreferredModuleBase(uint64_t address)
{
    return (address - PreferredImageBase) + EmulationImageBase;
}

uint64_t Executable::ConvertToPreferredImageBase(uint64_t address)
{
    return (address - EmulationImageBase) + PreferredImageBase;
}

LPVOID MapFileIntoMemory(const std::string& exePath, size_t* fileSize)
{
    std::ifstream exeFile(exePath, std::ios::binary | std::ios::in);
    if (!exeFile)
        return NULL;

    size_t fSize = std::filesystem::file_size(exePath);
    if (fSize == 0)
        return NULL;

    void* exeData = malloc(fSize);
    exeFile.read((char*)exeData, fSize);

    if (fileSize)
        *fileSize = fSize;

    return exeData;
}

uint64_t roundUp(uint64_t numToRound, uint64_t multiple)
{
    if (multiple == 0)
        return numToRound;

    uint64_t remainder = numToRound % multiple;
    if (remainder == 0)
        return numToRound;

    return numToRound + multiple - remainder;
}