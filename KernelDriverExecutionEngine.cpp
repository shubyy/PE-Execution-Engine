#include <iostream>
#include <format>

#include "unicorn/unicorn.h"
#include "Executable.h"
#include "EmulatorHooks.h"

uint64_t END_ADDRESS = 0x00;

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

    size_t uc_mem_size = roundUp((int) exec.imgSize, 4096);
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
    uint64_t r_rsp = startStackAddress - 64;
    uint64_t r_rbp = startStackAddress;

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
    uc_err err;
    
    uc_hook trace1;

    exec.EmulationEnd = END_ADDRESS;

    std::cout << "Image Base Address: " << exec.imgBase << std::endl;
    std::cout << "Emulation Start Address: " << (LPVOID) exec.EmulationStart << std::endl;
    std::cout << "Emulation End Address: " << (LPVOID) exec.EmulationEnd << std::endl;
    
    uc_hook_add(uc, &trace1, UC_HOOK_CODE, hook_instruction, NULL, exec.EmulationStart, exec.EmulationEnd);

    //Start Emulation
    err = uc_emu_start(uc, exec.EmulationStart, exec.EmulationEnd, 30 * 1000000, 0);
    if (err != UC_ERR_OK)
        std::cout << "Failed to emulate executable\n\nState: \n" << std::endl;

    std::cout << "Finished Emulating Executable to desired address!\n\nState: \n" << std::endl;

    uint64_t r_rdx;
    uint64_t r_rcx;
    uint64_t r_rdi;
    uint64_t r_rsi;
    uint64_t r_rax;

    uc_reg_read(uc, UC_X86_REG_RDX, &r_rdx);
    uc_reg_read(uc, UC_X86_REG_RCX, &r_rcx);
    uc_reg_read(uc, UC_X86_REG_RDI, &r_rdi);
    uc_reg_read(uc, UC_X86_REG_RSI, &r_rsi);
    uc_reg_read(uc, UC_X86_REG_RAX, &r_rax);

    std::cout << std::hex << "RAX: 0x" << r_rax << std::endl;
    std::cout << std::hex << "RCX: 0x" << r_rcx << std::endl;
    std::cout << std::hex << "RDX: 0x" << r_rdx << std::endl;
    std::cout << std::hex << "RDI: 0x" << r_rdi << std::endl;
    std::cout << std::hex << "RSI: 0x" << r_rsi << std::endl;

    return 0;

}