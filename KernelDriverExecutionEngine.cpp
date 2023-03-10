#include <iostream>
#include <string>
#include <format>
#include <vector>
#include <iomanip> 
#include "KernelDriverExecutionEngine.h"
#include "Emulator.h"
#include "unicorn/unicorn.h"
#include "Executable.h"
#include "EmulatorHooks.h"

#define LOAD_ADDRESS 0x140000000 //0xfffff807173b0000 

uint64_t END_ADDRESS = ULLONG_MAX;

Executable* exec;
Emulator* em;

void AddInitialBreakpoints()
{
    //em->AddBreakpoint(0x140A30398);
}

PDRIVER_OBJECT CreateFakeDriverObject()
{
    //Allocate Driver Object structure
    PDRIVER_OBJECT driverObject = new DRIVER_OBJECT();
    driverObject->Type = 0x4;
    driverObject->Size = 0x150;
    driverObject->Flags = 0x2;
    driverObject->DriverStart = (LPVOID)exec->EmulationImageBase;
    driverObject->DriverSize = exec->imgSize;
    driverObject->DriverInit = (LPVOID)exec->EmulationStart;
    return driverObject;
}

bool SetupEmulator()
{
    em = new Emulator();
    if (!em->init)
    {
        std::cout << "Failed to load unicorn!" << std::endl;
        return false;
    }
    
    uc_hook IAThook;

    uint64_t IATHookBase = 0x80000;
    uint64_t IATHookSize = 0x1000;
    //Setup IAT Hooks by filling func address with custom address
    em->AddMapping(IATHookBase, IATHookSize, UC_PROT_ALL, "IAT Hook");
    exec->HookImports(IATHookBase);
    uc_hook_add(em->uc, &IAThook, UC_HOOK_CODE, hook_IAT_exec, NULL, IATHookBase, IATHookBase + IATHookSize);

    uint64_t uc_mem_size = roundUp((int) exec->imgSize, 4096);
    //Allocate space for executable in unicorn
    em->AddMappingFromSource(exec->EmulationImageBase, uc_mem_size, exec->imgBase, exec->imgSize, UC_PROT_ALL, "Image");

    //Choose Heap and Stack
    uint64_t stack_bottom = roundUp(exec->EmulationImageBase + uc_mem_size - 0xFFFF000000, 0x1000);
    uint64_t initial_stack_Size = 32 * 1024;
    uint64_t stack_top = stack_bottom + initial_stack_Size;
    em->AddMapping(stack_bottom, initial_stack_Size, UC_PROT_READ | UC_PROT_WRITE, "Stack");

    //Start heap at bottom and stack at top
    uint64_t r_rsp = stack_top - 120;
    uint64_t r_rbp = r_rsp + 72;

    em->WriteReg(UC_X86_REG_RSP, &r_rsp);
    em->WriteReg(UC_X86_REG_RBP, &r_rbp);

    //Create fake driver object and reg path
    PDRIVER_OBJECT driverObject = CreateFakeDriverObject();
    const std::wstring reg_path = L"";

    uint64_t param_1_driverObject = exec->EmulationImageBase - 0xFF80000000;
    uint64_t param_2_registryPath = param_1_driverObject + 0x200;

    em->AddMappingFromSource(param_1_driverObject, roundUp(sizeof(DRIVER_OBJECT), 4096), driverObject, sizeof(DRIVER_OBJECT), UC_PROT_READ | UC_PROT_WRITE, "Parameters");

    em->WriteReg(UC_X86_REG_RAX, &exec->EmulationStart);
    em->WriteReg(UC_X86_REG_RCX, &param_1_driverObject);
    em->WriteReg(UC_X86_REG_RDI, &param_1_driverObject);
    em->WriteReg(UC_X86_REG_R15, &param_1_driverObject);
    em->WriteReg(UC_X86_REG_RDX, &param_2_registryPath);

    //Fake constant memory location in kernel
    size_t k_data_size = 0;
    uint64_t kernel_data_base = 0xfffff78000000000;
    LPVOID k_data = MapFileIntoMemory("./kernel_data.data", &k_data_size);
    em->AddMapping(kernel_data_base, roundUp(k_data_size, 4096), UC_PROT_ALL, "Kernel Data");
    em->WriteEmuMem(0xfffff78000000014, k_data, k_data_size);

    delete driverObject;
    return true;
}

int main(int argc, char* argv[])
{
    exec = new Executable("C:\\Users\\Shubham\\Desktop\\x96dbg.exe", LOAD_ADDRESS);
    if(!exec->bInitialised)
        std::cout << "Failed to load executable!" << std::endl; return -1;

    SetupEmulator();
    uc_err err;
    
    uc_hook trace1, trace2, trace3, trace4;

    exec->EmulationEnd = END_ADDRESS;

    std::cout << "\nEmulation Start Address: " << (LPVOID) exec->EmulationStart << std::endl;
    std::cout << "Emulation End Address: " << (LPVOID) exec->EmulationEnd << std::endl;
    std::cout << std::hex << "\nImage Mapping: 0x" << exec->EmulationImageBase << "-0x" << exec->EmulationImageBase + exec->imgSize << std::endl << std::endl;
    
    uc_hook_add(em->uc, &trace1, UC_HOOK_CODE, hook_instruction, NULL, exec->EmulationImageBase, exec->EmulationImageBase + exec->imgSize);
    //uc_hook_add(uc, &trace2, UC_HOOK_MEM_VALID, hook_memory, NULL, 0, LLONG_MAX);
    //uc_hook_add(uc, &trace3, UC_HOOK_MEM_INVALID, hook_invalid_memory, NULL, 0, LLONG_MAX);

    //Start Emulation
    AddInitialBreakpoints();
    bool success = false;//em->StartEmulation(exec->EmulationStart, exec->EmulationEnd, 0, 0);
    if (!success)
        std::cout << "\nFailed to emulate executable\n\nState: \n" << std::endl;
    else
        std::cout << "\nFinished Emulating Executable to desired address!\n\nState: \n" << std::endl;

    print_emulator_cpu_state();
    std::cout << std::endl;

    //size_t DriverObjectSize = sizeof(DRIVER_OBJECT);
    //PDRIVER_OBJECT driverObject = new DRIVER_OBJECT();
    //if (uc_mem_read(uc, param_1_driverObject, (LPVOID)driverObject, sizeof(driverObject)) == UC_ERR_OK)
    //{

        //std::cout << "Driver Object Major Functions:" << std::endl;
        //int size = sizeof(driverObject->MajorFunction) / sizeof(LPVOID);
        //for (int i = 0; i < size; i++)
            //std::cout << i << ": " << (LPVOID)driverObject->MajorFunction[i] << std::endl;
    //}

    //delete driverObject;

    return 0;

}