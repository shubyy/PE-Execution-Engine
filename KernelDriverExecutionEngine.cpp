#include <iostream>

#include "Executable.h"
#include "unicorn/unicorn.h"

int roundUp(int numToRound, int multiple)
{
    if (multiple == 0)
        return numToRound;

    int remainder = numToRound % multiple;
    if (remainder == 0)
        return numToRound;

    return numToRound + multiple - remainder;
}

uc_engine * SetupEmulator(const Executable& exec)
{
    uc_engine* uc;
    uc_err err;

    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err != UC_ERR_OK)
    {
        std::cout << "Failed to load unicorn!" << std::endl;
        return NULL;
    }

    size_t uc_mem_size = roundUp(exec.imgSize, 4096);
    //Allocate space for executable in unicorn
    uc_mem_map(uc, exec.optionalHeader->ImageBase, uc_mem_size, uc_prot::UC_PROT_ALL);
    if (uc_mem_write(uc, exec.optionalHeader->ImageBase, exec.imgBase, exec.imgSize) != UC_ERR_OK)
    {
        std::cout << "Failed to write to memory" << std::endl;
        return NULL;
    }

    //Find suitable stack location
    long long startStackAddress = 0x7ff000000;
    while (abs(startStackAddress - (long long)exec.optionalHeader->ImageBase) < 0x8ffff)
    {
        startStackAddress += 4096;
        if (startStackAddress > 0xffffffffffff)
        {
            uc_close(uc);
            return NULL;
        } 
    }

    size_t initialStackSize = 1024 * 1024;
    long long allocateAddress = startStackAddress - initialStackSize;


    //Allocate stack of executable
    uc_mem_map(uc, allocateAddress, initialStackSize, UC_PROT_READ | UC_PROT_WRITE);
    int r_rsp = startStackAddress;
    int r_rbp = startStackAddress;

    uc_reg_write(uc, UC_X86_REG_RSP, &r_rsp);
    uc_reg_write(uc, UC_X86_REG_RBP, &r_rbp);

    return uc;
}

int main(int argc, char* argv[])
{
    Executable exec("C:\\Users\\Shubham\\Desktop\\EAC\\EasyAntiCheat.sys");
    if(exec.bInitialised)
        std::cout << "Loaded executable!" << std::endl;

    uc_engine *uc = SetupEmulator(exec);
    
}