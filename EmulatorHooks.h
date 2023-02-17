#pragma once
#include <Windows.h>
#include <string>

#include "unicorn/unicorn.h"

void hook_instruction(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
