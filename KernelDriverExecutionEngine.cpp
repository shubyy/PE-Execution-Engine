// KernelDriverExecutionEngine.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <filesystem>
#include <iostream>
#include <string>
#include <fstream>

size_t fileSize = 0;

HANDLE MapExecutableIntoMemory(const std::string& exePath)
{
    std::ifstream exeFile(exePath, std::ios::binary | std::ios::ate | std::ios::in);
    if (!exeFile)
        return NULL;

    fileSize = std::filesystem::file_size(exePath);
    if (fileSize < 0x100)
        return NULL;

    void* exeData = malloc(fileSize);
    
    exeFile.read((char*)exeData, fileSize);
    return exeData;
}

bool CheckMagicHeader(PIMAGE_DOS_HEADER execHndle)
{
    if (execHndle->e_magic != 0x5A4D)
        return false;
}

bool LoadExecutable(const std::string& exePath)
{
    HANDLE exeBase = MapExecutableIntoMemory(exePath);
    PIMAGE_DOS_HEADER imgHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(exeBase);
    if (!exeBase || !CheckMagicHeader(imgHeader))
    {
        
        return false;
    }

    PIMAGE_NT_HEADERS ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((char *) exeBase + imgHeader->e_lfanew);

    PIMAGE_FILE_HEADER fileHeader = &ntHeader->FileHeader;
    PIMAGE_OPTIONAL_HEADER optionalHeader = &ntHeader->OptionalHeader;

    LPVOID imgBase = VirtualAlloc((LPVOID) optionalHeader->ImageBase, 
                                    optionalHeader->SizeOfImage,
                             MEM_COMMIT | MEM_RESERVE, 
                                  PAGE_READWRITE);

    if (!imgBase)
    {
        free(exeBase);
        return false;
    }
        

}

int main(int argc, char* argv[])
{
    bool success = LoadExecutable("C:/Users/Shubham/Desktop/EAC/EasyAntiCheat.sys");
    if (success)
    {
        std::cout << "Successfully loaded executable" << std::endl;
    }
}