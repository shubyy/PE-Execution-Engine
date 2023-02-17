#include <iostream>
#include "EmulatorHooks.h"

void hook_instruction(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	uint64_t r_rip;
	uc_reg_read(uc, UC_X86_REG_RIP, &r_rip);
	std::cout << "Executing instruction at: " << (LPVOID) r_rip << std::endl;
}
