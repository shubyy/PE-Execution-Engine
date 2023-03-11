#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>

#include "EmulatorHooks.h"
#include "Executable.h"

extern uint64_t stack_top;
extern uint64_t stack_bottom;
extern uint64_t sysRange_bottom;
extern uint64_t sysRange_top;
extern uint64_t param_1_driverObject;
extern uint64_t param_2_registryPath;

extern std::vector<uint64_t> emulator_breakpoints;

bool step = false;

Executable* exec;

std::string hexStr(const uint8_t* data, int len)
{
	std::stringstream ss;
	ss << std::hex;

	for (int i = len-1; i >= 0; i--)
		ss << std::setw(2) << std::setfill('0') << (int)data[i];

	return ss.str();
}

static bool AddressInRange(uint64_t address, uint64_t low, uint64_t high)
{
	return (address >= low && address <= high);
}

void print_insn(ZydisDisassembledInstruction *instruction)
{
	std::cout << (LPVOID)instruction->runtime_address << "\t" << instruction->text << std::endl;
}

static bool IsRing0Instruction(ZydisDisassembledInstruction* instruction)
{

}

void print_emulator_cpu_state(uc_engine* uc)
{
	uint64_t r_rax;
	uint64_t r_rbx;
	uint64_t r_rcx;
	uint64_t r_rdx;
	uint64_t r_rdi;
	uint64_t r_rsi;
	uint64_t r_rip;
	uint64_t r_rbp;
	uint64_t r_rsp;
	uint64_t r_r8;
	uint64_t r_r9;
	uint64_t r_r10;
	uint64_t r_r11;
	uint64_t r_r12;
	uint64_t r_r13;
	uint64_t r_r14;
	uint64_t r_r15;
	uint64_t r_rflags;

	uint8_t r_xmm0[16];
	uint8_t r_xmm1[16];
	uint8_t r_xmm2[16];
	uint8_t r_xmm3[16];
	uint8_t r_xmm4[16];
	uint8_t r_xmm5[16];
	uint8_t r_xmm6[16];
	uint8_t r_xmm7[16];
	uint8_t r_xmm8[16];
	uint8_t r_xmm9[16];
	uint8_t r_xmm10[16];
	uint8_t r_xmm11[16];
	uint8_t r_xmm12[16];
	uint8_t r_xmm13[16];
	uint8_t r_xmm14[16];
	uint8_t r_xmm15[16];

	uc_reg_read(uc, UC_X86_REG_RIP, &r_rip);
	uc_reg_read(uc, UC_X86_REG_RAX, &r_rax);
	uc_reg_read(uc, UC_X86_REG_RBX, &r_rbx);
	uc_reg_read(uc, UC_X86_REG_RCX, &r_rcx);
	uc_reg_read(uc, UC_X86_REG_RDX, &r_rdx);
	uc_reg_read(uc, UC_X86_REG_RDI, &r_rdi);
	uc_reg_read(uc, UC_X86_REG_RSI, &r_rsi);
	uc_reg_read(uc, UC_X86_REG_RBP, &r_rbp);
	uc_reg_read(uc, UC_X86_REG_RSP, &r_rsp);
	uc_reg_read(uc, UC_X86_REG_R8, &r_r8);
	uc_reg_read(uc, UC_X86_REG_R9, &r_r9);
	uc_reg_read(uc, UC_X86_REG_R10, &r_r10);
	uc_reg_read(uc, UC_X86_REG_R11, &r_r11);
	uc_reg_read(uc, UC_X86_REG_R12, &r_r12);
	uc_reg_read(uc, UC_X86_REG_R13, &r_r13);
	uc_reg_read(uc, UC_X86_REG_R14, &r_r14);
	uc_reg_read(uc, UC_X86_REG_R15, &r_r15);
	uc_reg_read(uc, UC_X86_REG_RFLAGS, &r_rflags);

	uc_reg_read(uc, UC_X86_REG_XMM0, &r_xmm0);
	uc_reg_read(uc, UC_X86_REG_XMM1, &r_xmm1);
	uc_reg_read(uc, UC_X86_REG_XMM2, &r_xmm2);
	uc_reg_read(uc, UC_X86_REG_XMM3, &r_xmm3);
	uc_reg_read(uc, UC_X86_REG_XMM4, &r_xmm4);
	uc_reg_read(uc, UC_X86_REG_XMM5, &r_xmm5);
	uc_reg_read(uc, UC_X86_REG_XMM6, &r_xmm6);
	uc_reg_read(uc, UC_X86_REG_XMM7, &r_xmm7);
	uc_reg_read(uc, UC_X86_REG_XMM8, &r_xmm8);
	uc_reg_read(uc, UC_X86_REG_XMM9, &r_xmm9);
	uc_reg_read(uc, UC_X86_REG_XMM10, &r_xmm10);
	uc_reg_read(uc, UC_X86_REG_XMM11, &r_xmm11);
	uc_reg_read(uc, UC_X86_REG_XMM12, &r_xmm12);
	uc_reg_read(uc, UC_X86_REG_XMM13, &r_xmm13);
	uc_reg_read(uc, UC_X86_REG_XMM14, &r_xmm14);
	uc_reg_read(uc, UC_X86_REG_XMM15, &r_xmm15);

	std::cout << std::hex << "RIP: 0x" << r_rip << std::endl;
	std::cout << std::hex << "RAX: 0x" << r_rax << " RBX: 0x" << r_rbx << " RCX: 0x" << r_rcx << " RDX: 0x" << r_rdx << std::endl;
	std::cout << std::hex << "RDI: 0x" << r_rdi << " RSI: 0x" << r_rsi << " RBP: 0x" << r_rbp << " RSP: 0x" << r_rsp << std::endl;
	std::cout << std::hex << " R8: 0x" << r_r8 << "  R9: 0x" << r_r9 << "   R10: 0x" << r_r10 << " R11: 0x" << r_r11 << std::endl;
	std::cout << std::hex << "R12: 0x" << r_r12 << " R13: 0x" << r_r13 << " R14: 0x" << r_r14 << " R15: 0x" << r_r15 << std::endl;

	unsigned short int cf = (r_rflags & (1 << 0)) > 0;
	unsigned short int pf = (r_rflags & (1 << 2)) > 0;
	unsigned short int af = (r_rflags & (1 << 4)) > 0;
	unsigned short int zf = (r_rflags & (1 << 6)) > 0;
	unsigned short int sf = (r_rflags & (1 << 7)) > 0;
	unsigned short int of = (r_rflags & (1 << 11)) > 0;
	std::cout << "CF = " << cf << " PF = " << pf << " AF = " << af << " ZF = " << zf << " SF = " << sf << " OF = " << of << std::endl << std::endl;

	std::cout << " XMM0: " << hexStr(r_xmm0, 16) << std::endl;
	std::cout << " XMM1: " << hexStr(r_xmm1, 16) << std::endl;
	std::cout << " XMM2: " << hexStr(r_xmm2, 16) << std::endl;
	std::cout << " XMM3: " << hexStr(r_xmm3, 16) << std::endl;
	std::cout << " XMM4: " << hexStr(r_xmm4, 16) << std::endl;
	std::cout << " XMM5: " << hexStr(r_xmm5, 16) << std::endl;
	std::cout << " XMM6: " << hexStr(r_xmm6, 16) << std::endl;
	std::cout << " XMM7: " << hexStr(r_xmm7, 16) << std::endl;
	std::cout << " XMM8: " << hexStr(r_xmm8, 16) << std::endl;
	std::cout << " XMM9: " << hexStr(r_xmm9, 16) << std::endl;
	std::cout << "XMM10: " << hexStr(r_xmm10, 16) << std::endl;
	std::cout << "XMM11: " << hexStr(r_xmm11, 16) << std::endl;
	std::cout << "XMM12: " << hexStr(r_xmm12, 16) << std::endl;
	std::cout << "XMM13: " << hexStr(r_xmm13, 16) << std::endl;
	std::cout << "XMM14: " << hexStr(r_xmm14, 16) << std::endl;
	std::cout << "XMM15: " << hexStr(r_xmm15, 16) << std::endl << std::endl;
}

void print_current_emulator_stack(uc_engine* uc, int count)
{
	uint64_t r_rsp;
	uc_reg_read(uc, UC_X86_REG_RSP, &r_rsp);

	uint64_t currentStackPtr = r_rsp;
	uint64_t endStackPrint = currentStackPtr + count * sizeof(uint64_t);
	while (currentStackPtr < endStackPrint)
	{
		uint64_t value;
		uc_err err;
		err = uc_mem_read(uc, currentStackPtr, &value, sizeof(uint64_t));
		if (err == UC_ERR_OK)
		{
			std::cout << (LPVOID)currentStackPtr << ": " << (LPVOID)value << std::endl;
			currentStackPtr += sizeof(uint64_t);
		}
		else
			return;
	}
}

bool isAddressBreakpoint(uint64_t address)
{
	for (uint64_t breakpoint : emulator_breakpoints)
		if (address == breakpoint)
			return true;
	
	return false;
}

void AddBreakpoint(uint64_t address)
{
	emulator_breakpoints.push_back(address);
}

void RemoveBreakpoint(int index)
{
	return;
}

void print_memory(uc_engine* uc, uint64_t address, size_t size)
{
	uint8_t *val = (uint8_t*) malloc(size);
	if(uc_mem_read(uc, address, val, size) == UC_ERR_OK)
		std::cout << (LPVOID)address << ": " << hexStr(val, size) << std::endl;
}

void HandleUserInput(uc_engine *uc)
{
	while (1)
	{
		std::string input;
		std::cin >> input;
		if (input == "c")
		{
			step = false;
			return;
		}
		else if (input == "s")
		{
			step = true;
			return;
		}
		else if (input == "irsp")
		{
			print_current_emulator_stack(uc, 10);
		}
		else if (input == "b")
		{
			std::cout << "Enter Address: ";

			std::string address_string;
			std::cin >> address_string;
			uint64_t address = std::stoull(address_string, nullptr, 16);

			AddBreakpoint(address);
			std::cout << "Added Breakpoint: " << (LPVOID)address << std::endl;
		}
		else if (input.substr(0, 2) == "rb")
		{
			std::cout << "Enter Index: ";

			std::string str_index;
			std::cin >> str_index;
			int index = std::stoi(str_index);

			std::cout << "Removing Breakpoint: " << (LPVOID)index << std::endl;

			std::vector<uint64_t>::iterator it = emulator_breakpoints.begin();
			std::advance(it, index);
			emulator_breakpoints.erase(it);
		}
		else if (input == "stack")
		{
			std::cout << "Enter Count: ";

			std::string str_count;
			std::cin >> str_count;
			int count = std::stoi(str_count);
			count = min(count, 20);

			std::cout << "Enter Size To Print: ";

			std::string str_size;
			std::cin >> str_size;
			int size = std::stoi(str_size);
			size = min(size, 16);

			uint64_t r_rsp = 0x0;
			uc_reg_read(uc, UC_X86_REG_RSP, &r_rsp);

			for (int i = 0; i < count; i++)
			{
				print_memory(uc, r_rsp + i * size, size);
			}
		}
	}
	
}

void hook_instruction(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	if (isAddressBreakpoint(address) || step)
	{
		LPVOID real_address = (LPVOID)((BYTE*)exec->imgBase + (address - exec->optionalHeader->ImageBase));
		ZydisDisassembledInstruction instruction;
		if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, address, real_address, 16, &instruction)))
		{
			print_insn(&instruction);
			print_emulator_cpu_state(uc);

			HandleUserInput(uc);
		}
	}
}

void hook_ring0_instruction(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	LPVOID real_address = (LPVOID)((BYTE*)exec->imgBase + (address - exec->EmulationImageBase));
	ZydisDisassembledInstruction instruction;
	if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, address, real_address, 16, &instruction)))
	{
		if (IsRing0Instruction(&instruction))
			print_insn(&instruction);
	}
}

void hook_jump_instruction(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	LPVOID real_address = (LPVOID)((BYTE*)exec->imgBase + (address - exec->EmulationImageBase));
	ZydisDisassembledInstruction instruction;
	if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, address, real_address, 16, &instruction)))
	{
		ZydisMnemonic mnem = instruction.info.mnemonic;
		//if (mnem >= ZYDIS_MNEMONIC_JB && mnem <= ZYDIS_MNEMONIC_JZ)
		//{
			//print_insn(&instruction);
			//print_emulator_cpu_state(uc);
		//}
		if (mnem == ZYDIS_MNEMONIC_CALL)
		{
			print_insn(&instruction);
			print_emulator_cpu_state(uc);
		}
		//else if (mnem == ZYDIS_MNEMONIC_RET)
		//{
			//print_insn(&instruction);
			//print_emulator_cpu_state(uc);
		//}
	}
}

void hook_memory(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data)
{
	uint64_t mem_value = 0x0;
	uint64_t r_rip;
	uc_reg_read(uc, UC_X86_REG_RIP, &r_rip);
	std::string location;
	//Get Location of Address
	if (address >= stack_bottom && address <= stack_top)
	{
		location = "Stack Address: ";
	}
	else if (address >= exec->EmulationImageBase && address <= exec->EmulationImageBase + exec->imgSize)
	{
		location = "Image Address: ";
	}
	else if (address >= sysRange_bottom && address <= sysRange_top)
	{
		location = "System Address: ";
	}
		

	switch (type)
	{
	case UC_MEM_WRITE:
		std::cout << (LPVOID)r_rip << ":\tValue: " << (LPVOID)value << ":\tWritten To " << location << (LPVOID)address << "\tSize: " << (LPVOID)size << std::endl;
		break;
	case UC_MEM_READ:
		uc_mem_read(uc, address, &mem_value, size);
		std::cout << (LPVOID)r_rip << ":\tValue: " << (LPVOID)mem_value << ":\tRead from " << location << (LPVOID)address << "\tSize : " << (LPVOID)size << std::endl;
		break;
	case UC_MEM_FETCH:
		std::cout << (LPVOID)r_rip << ":\tValue: " << (LPVOID)value << ":\tFetched from " << location << (LPVOID)address << "\tSize: " << (LPVOID)size << std::endl;
		break;
	}
}

void hook_custom_memory(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data)
{
	if (address >= param_1_driverObject && address <= param_2_registryPath + 0x8)
	{

	}
}

void hook_parameter_memory(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data)
{
	uint64_t mem_value = 0x0;
	uint64_t r_rip;
	uc_reg_read(uc, UC_X86_REG_RIP, &r_rip);
	std::string location;
	//Get Location of Address
	if (address >= param_1_driverObject && address <= param_2_registryPath + 0x8)
	{
		switch (type)
		{
		case UC_MEM_WRITE:
			std::cout << (LPVOID)r_rip << ":\tValue: " << (LPVOID)value << ":\tWritten To " << (LPVOID)address << "\tSize: " << (LPVOID)size << std::endl;
			break;
		case UC_MEM_READ:

			uc_mem_read(uc, address, &mem_value, size);
			std::cout << (LPVOID)r_rip << ":\tValue: " << (LPVOID)mem_value << ":\tRead from " << (LPVOID)address << "\tSize : " << (LPVOID)size << std::endl;
			break;
		case UC_MEM_FETCH:
			std::cout << (LPVOID)r_rip << ":\tValue: " << (LPVOID)value << ":\tFetched from " << (LPVOID)address << "\tSize: " << (LPVOID)size << std::endl;
			break;
		}
	}
}

void hook_invalid_memory(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data)
{
	uint64_t r_rip;
	uc_reg_read(uc, UC_X86_REG_RIP, &r_rip);
	std::cout << (LPVOID) r_rip << ":\tAccess Violation at Address: " << (LPVOID)address << "\tSize: " << (LPVOID)size << std::endl;
}

bool InitDisassembler(Executable *created_exec)
{
	exec = created_exec;
	return true;
}