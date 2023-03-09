#pragma once
#include <Windows.h>
#include <string>

#include "unicorn/unicorn.h"
#include "Zydis/Zydis.h"

class Executable;

//Hooks
void hook_instruction(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
void hook_memory(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
void hook_jump_instruction(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
void hook_ring0_instruction(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
void hook_parameter_memory(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
void hook_invalid_memory(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);

bool InitDisassembler(Executable* created_exec);

//Display
void print_emulator_cpu_state(uc_engine* uc);
