#include <iostream>
#include <string>
#include <format>
#include <vector>
#include <iomanip> 
#include "KernelDriverExecutionEngine.h"

#define LOAD_ADDRESS 0xfffff80150fe0000 //0x140000000 //0xFFFFF80714CE0000 

uint64_t END_ADDRESS = ULLONG_MAX;
uint64_t stack_top = 0x0;
uint64_t stack_bottom = 0x0;
uint64_t sysRange_bottom = 0x0;
uint64_t sysRange_top = 0x0;
uint64_t param_1_driverObject = 0x0;
uint64_t param_2_registryPath = 0x0;

#include "unicorn/unicorn.h"
#include "Executable.h"
#include "EmulatorHooks.h"

std::vector <uint64_t> emulator_breakpoints = {
    //0x1405feef1 //Decode Value
    0x1409b66e7
    //0x140C1913A,
    //0x140C19143,
    //0x140C19180,
    //0x140C827C0,
    //0x140C827C9
};

uc_engine * SetupEmulator(const Executable& exec)
{
    uc_engine* uc;
    uc_err err;
    uc_hook trace2;

    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err != UC_ERR_OK)
    {
        std::cout << "Failed to load unicorn!" << std::endl;
        return NULL;
    }

    uint64_t uc_mem_size = roundUp((int) exec.imgSize, 4096);
    //Allocate space for executable in unicorn
    uc_mem_map(uc, exec.EmulationImageBase, uc_mem_size, uc_prot::UC_PROT_ALL);
    if (uc_mem_write(uc, exec.EmulationImageBase, exec.imgBase, exec.imgSize) != UC_ERR_OK)
    {
        std::cout << "Failed to write to memory" << std::endl;
        return NULL;
    }

    //Choose Heap and Stack
    stack_bottom = roundUp(exec.EmulationImageBase + uc_mem_size + 0xFF0000, 0x1000);
    uint64_t initial_stack_Size = 32 * 1024;
    stack_top = stack_bottom + initial_stack_Size;

    sysRange_bottom = roundUp(exec.EmulationImageBase - 0xff00000000, 0x1000);
    uint64_t initial_sys_range = 4 * 1024 * 1024;
    sysRange_top = sysRange_bottom + initial_sys_range;

    //Allocate stack of executable
    uc_mem_map(uc, stack_bottom, initial_stack_Size, uc_prot::UC_PROT_ALL);

    //Allocate system range
    uc_mem_map(uc, sysRange_bottom, initial_sys_range, uc_prot::UC_PROT_ALL);

    std::cout << std::hex << "\Stack Range Mapping: 0x" << stack_bottom << "-0x" << stack_top << std::endl;

    //Start heap at bottom and stack at top
    uint64_t r_rsp = stack_top - 120;
    uint64_t r_rbp = r_rsp + 72;

    uc_reg_write(uc, UC_X86_REG_RSP, &r_rsp);
    uc_reg_write(uc, UC_X86_REG_RBP, &r_rbp);

    //Allocate Driver Object structure
    size_t DriverObjectSize = sizeof(DRIVER_OBJECT);
    PDRIVER_OBJECT driverObject = new DRIVER_OBJECT();
    driverObject->Type = 0x4;
    driverObject->Size = 0x150;
    driverObject->Flags = 0x2;
    driverObject->DriverStart = (LPVOID) exec.EmulationImageBase;
    driverObject->DriverSize = exec.imgSize;
    driverObject->DriverInit = (LPVOID) exec.EmulationStart;

    std::cout << std::hex << "\nSystem Range Mapping: 0x" << sysRange_bottom << "-0x" << sysRange_top << std::endl;

    const std::wstring reg_path = L"";

    param_1_driverObject = sysRange_bottom + 0x6e0;
    param_2_registryPath = roundUp(param_1_driverObject + DriverObjectSize + 0x800, 0x16);

    uc_mem_write(uc, param_1_driverObject, driverObject, DriverObjectSize);
    uc_reg_write(uc, UC_X86_REG_RAX, &exec.EmulationStart);
    uc_reg_write(uc, UC_X86_REG_RCX, &param_1_driverObject);
    uc_reg_write(uc, UC_X86_REG_RDI, &param_1_driverObject);
    uc_reg_write(uc, UC_X86_REG_R15, &param_1_driverObject);
    uc_reg_write(uc, UC_X86_REG_RDX, &param_2_registryPath);

    delete driverObject;

    std::cout << "\Driver Object: 0x" << (LPVOID)param_1_driverObject << std::endl;
    std::cout << "Reg Path: 0x" << (LPVOID)param_2_registryPath << std::endl;

    emulator_breakpoints.push_back(exec.EmulationStart);

    return uc;
}

int main(int argc, char* argv[])
{
    Executable exec("", LOAD_ADDRESS);
    if(exec.bInitialised)
        std::cout << "Loaded executable!" << std::endl;

    uc_engine *uc = SetupEmulator(exec);
    uc_err err;
    
    uc_hook trace1, trace2, trace3, trace4;

    exec.EmulationEnd = END_ADDRESS;

    std::cout << "\nEmulation Start Address: " << (LPVOID) exec.EmulationStart << std::endl;
    std::cout << "Emulation End Address: " << (LPVOID) exec.EmulationEnd << std::endl;
    std::cout << std::hex << "\nImage Mapping: 0x" << exec.EmulationImageBase << "-0x" << exec.EmulationImageBase + exec.imgSize << std::endl << std::endl;
    
    if (!InitDisassembler(&exec))
        return -1;
    
    uc_hook_add(uc, &trace1, UC_HOOK_CODE, hook_instruction, NULL, 0, LLONG_MAX);
    //uc_hook_add(uc, &trace2, UC_HOOK_MEM_VALID, hook_memory, NULL, 0, LLONG_MAX);
    //uc_hook_add(uc, &trace3, UC_HOOK_MEM_INVALID, hook_invalid_memory, NULL, 0, LLONG_MAX);

    //Start Emulation
    err = uc_emu_start(uc, exec.EmulationStart, exec.EmulationEnd, 0 * 30 * 1000000, 0);
    if (err != UC_ERR_OK)
        std::cout << "\nFailed to emulate executable\n\nState: \n" << std::endl;
    else
        std::cout << "\nFinished Emulating Executable to desired address!\n\nState: \n" << std::endl;

    print_emulator_cpu_state(uc);
    std::cout << std::endl;

    size_t DriverObjectSize = sizeof(DRIVER_OBJECT);
    PDRIVER_OBJECT driverObject = new DRIVER_OBJECT();
    if (uc_mem_read(uc, param_1_driverObject, (LPVOID)driverObject, sizeof(driverObject)) == UC_ERR_OK)
    {

        std::cout << "Driver Object Major Functions:" << std::endl;
        int size = sizeof(driverObject->MajorFunction) / sizeof(LPVOID);
        //for (int i = 0; i < size; i++)
            //std::cout << i << ": " << (LPVOID)driverObject->MajorFunction[i] << std::endl;
    }

    delete driverObject;

    return 0;

}