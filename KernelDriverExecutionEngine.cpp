#include <iostream>

#include "Executable.h"
#include "unicorn/unicorn.h"








int main(int argc, char* argv[])
{
    Executable exec("C:\\Users\\Shubham\\Desktop\\EAC\\EasyAntiCheat.sys");
    if(exec.bInitialised)
        std::cout << "Loaded executable!" << std::endl;

    uc_engine* uc;
    uc_err err;

    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err != UC_ERR_OK)
    {
        std::cout << "Failed to load unicorn!" << std::endl;
        return -1;
    }

    uc_mem_map(uc, exec.optionalHeader->ImageBase, exec.imgSize, uc_prot::UC_PROT_ALL);
    if (uc_mem_write(uc, exec.optionalHeader->ImageBase, exec.imgBase, exec.imgSize) != UC_ERR_OK)
    {
        std::cout << "Failed to write to memory" << std::endl;
        return -1;
    }

}