#include <iostream>
#include <iomanip>
#include <sstream>

#include "EmulatorHooks.h"
#include "Emulator.h"
#include "Executable.h"
#include "Zydis/Zydis.h"

class Emulator;

extern Executable* exec;
extern Emulator* em;

size_t skip_first = 15000;
size_t jump_count = 0;

bool check = false;

inline uint64_t convertFromPreferredModuleBase(uint64_t address)
{
	return (address - exec->optionalHeader->ImageBase) + exec->EmulationImageBase;
}

inline uint64_t ConvertToPreferredImageBase(uint64_t address)
{
	return (address - exec->EmulationImageBase) + exec->optionalHeader->ImageBase;
}

bool addressBlacklisted(uint64_t address)
{
	uint64_t prefAddress = ConvertToPreferredImageBase(address);
	//some copy encrypt function
	if(address > 0x14000c77c && address < 0x14000c8fc)
		return true;

	//memmove
	if (address > 140080240 && address < 0x1400803a9)
		return true;

	return false;
}



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
	return false;
}

void print_call_stack()
{
	for (int i = em->callstack.size() - 1; i >= 0; --i)
		print_insn_at( em->callstack[i] );
}

void print_emulator_cpu_state()
{
	uc_engine* uc = em->uc;
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
	std::cout << std::hex << " R8: 0x" << r_r8  << "  R9: 0x" << r_r9  << " R10: 0x" << r_r10 << " R11: 0x" << r_r11 << std::endl;
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

void print_insn_at(uint64_t address)
{
	LPVOID real_address = (LPVOID)((BYTE*)exec->imgBase + (address - exec->EmulationImageBase));
	ZydisDisassembledInstruction instruction;
	if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, address, real_address, 16, &instruction)))
		print_insn(&instruction);
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
	for (uint64_t breakpoint : em->emulator_breakpoints)
		if (address == breakpoint)
			return true;
	
	return false;
}

void print_memory(uint64_t address, size_t size)
{
	uc_engine* uc = em->uc;
	uint8_t *val = (uint8_t*) malloc(size);
	if(uc_mem_read(uc, address, val, size) == UC_ERR_OK)
		std::cout << (LPVOID)address << ": " << hexStr(val, size) << std::endl;
}

void HandleUserInput()
{
	uc_engine* uc = em->uc;
	while (1)
	{
		std::string input;
		std::cin >> input;
		if (input == "c")
		{
			em->step = false;
			return;
		}
		else if (input == "s")
		{
			em->step = true;
			return;
		}
		else if (input[0] == 'b')
		{
			if (input[1] == 'e')
			{
				em->breakOnImport = !em->breakOnImport;
				std::cout << "Break on Export:  " << (LPVOID)em->breakOnImport << std::endl;
				continue;
			}
			
			std::cout << "Enter Address: ";

			std::string address_string;
			std::cin >> address_string;
			uint64_t address = std::stoull(address_string, nullptr, 16);
			uint64_t bpAddress = address;

			if (input[1] == 'm')
			{
				//break using to module base address
				bpAddress = (address - exec->optionalHeader->ImageBase) + exec->EmulationImageBase;
			}
			
			em->AddBreakpoint(bpAddress);
			std::cout << "Added Breakpoint: " << (LPVOID)bpAddress << std::endl;
		}
		else if (input == "rb")
		{
			std::cout << "Enter Index: ";

			std::string str_index;
			std::cin >> str_index;
			int index = std::stoi(str_index);

			if (index >= em->emulator_breakpoints.size())
			{
				std::cout << "Invalid Index" << std::endl;
				continue;
			}

			std::vector<uint64_t>::iterator it = em->emulator_breakpoints.begin();
			std::advance(it, index);
			std::cout << "Removing Breakpoint: " << (LPVOID) *it << std::endl;
			em->emulator_breakpoints.erase(it);
		}
		else if (input == "stack")
		{
			std::cout << "Enter Count: ";

			std::string str_count;
			std::cin >> str_count;
			int count = std::stoi(str_count);
			count = min(count, 100);

			std::cout << "Enter Size To Print: ";

			std::string str_size;
			std::cin >> str_size;
			int size = std::stoi(str_size);
			size = min(size, 16);

			uint64_t r_rsp = 0x0;
			uc_reg_read(uc, UC_X86_REG_RSP, &r_rsp);

			for (int i = 0; i < count; i++)
			{
				print_memory(r_rsp + i * size, size);
			}
		}
		else if (input == "return")
		{
			std::cout << "Enter Hex Value to return from function: ";

			std::string value_string;
			std::cin >> value_string;
			uint64_t value = std::stoull(value_string, nullptr, 16);

			em->WriteReg(UC_X86_REG_RAX, &value);
			std::cout << "SET RAX TO: " << (LPVOID)value << std::endl;
		}
		else if (input == "callstack")
			print_call_stack();
		else if (input == "mem")
		{
			std::cout << "Enter Address: ";
			std::string address_string;
			std::cin >> address_string;
			uint64_t address = std::stoull(address_string, nullptr, 16);
			std::cout << "Enter Size: ";
			std::string size_string;
			std::cin >> size_string;
			uint64_t size = std::stoull(size_string);
			print_memory(address, size);
		}
		else if (input == "help")
		{
			std::cout << "c\t\t\t- Continue Execution" << std::endl;
			std::cout << "s\t\t\t- Step Execution" << std::endl;
			std::cout << "b\t\t\t- Add Breakpoint" << std::endl;
			std::cout << "be\t\t\t- Toggle Break on Export" << std::endl;
			std::cout << "rb\t\t\t- Remove Breakpoint" << std::endl;
			std::cout << "stack\t\t\t- Print Stack" << std::endl;
			std::cout << "return\t\t\t- Set RAX to Value" << std::endl;
			std::cout << "call\t\t\t- Print Call Stack" << std::endl;
			std::cout << "mem\t\t\t- Print Memory" << std::endl;
			std::cout << "help\t\t\t- Print Help" << std::endl;
		}
		else
			std::cout << "Unknown Command" << std::endl;
	}
	
}

void hook_instruction(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	LPVOID real_address = (LPVOID)((BYTE*)exec->imgBase + (address - exec->EmulationImageBase));
	ZydisDisassembledInstruction instruction;
	
	if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, address, real_address, 16, &instruction)))
	{
		ZydisMnemonic mnem = instruction.info.mnemonic;
		if (isAddressBreakpoint(address) || em->step)
		{
			std::cout << std::endl << "+" << jump_count << std::endl;
			print_insn(&instruction);
			print_emulator_cpu_state();
			HandleUserInput();
		}

		if (mnem == ZYDIS_MNEMONIC_CALL)
			em->PushCall(address);
		else if (mnem == ZYDIS_MNEMONIC_RET)
			em->PopCall();
	}
}

void hook_ring0_instruction(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	LPVOID real_address = (LPVOID)((BYTE*)exec->imgBase + (address - exec->EmulationImageBase));
	ZydisDisassembledInstruction instruction;

	if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, address, real_address, 16, &instruction)))
	{
		ZydisInstructionAttributes attributes = instruction.info.attributes;
		if (attributes & ZYDIS_ATTRIB_IS_PRIVILEGED)
		{
			std::cout << std::endl << "+" << jump_count << std::endl;
			print_insn(&instruction);
			print_emulator_cpu_state();
			HandleUserInput();
		}
	}
}

void hook_register(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	LPVOID real_address = (LPVOID)((BYTE*)exec->imgBase + (address - exec->EmulationImageBase));
	ZydisDisassembledInstruction instruction;
	if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, address, real_address, 16, &instruction)))
	{
		std::string text = instruction.text;
		if (text.find("xmm5") != std::string::npos)
		{
			std::cout << std::endl << "+" << jump_count << std::endl;
			print_insn(&instruction);
			print_emulator_cpu_state();
			HandleUserInput();
		}
	}
}

void GetImportFromAddress(uint64_t address, PIMAGE_IMPORT_DESCRIPTOR* module, PIMAGE_IMPORT_BY_NAME* import)
{
	//Calculate hook function from address
	uint64_t funcHookOffset = address - exec->IATHookBase;

	PIMAGE_OPTIONAL_HEADER optionalHeader = exec->optionalHeader;
	if (optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)exec->imgBase + optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		uint64_t startImportDesc = (uint64_t)importDesc;
		while (importDesc->Name)
		{
			ULONG_PTR* OFT = (ULONG_PTR*)((BYTE*)exec->imgBase + importDesc->OriginalFirstThunk);
			ULONG_PTR* FT = (ULONG_PTR*)((BYTE*)exec->imgBase + importDesc->FirstThunk);

			if (!OFT)
				OFT = FT;

			for (; *OFT; ++OFT, ++FT)
			{
				uint64_t funcIATOffset = (uint64_t)OFT - (uint64_t)startImportDesc;
				if (funcIATOffset == funcHookOffset)
				{
					//Function Match
					PIMAGE_IMPORT_BY_NAME IATImport = (PIMAGE_IMPORT_BY_NAME)((BYTE*)exec->imgBase + *OFT);
					*import = IATImport;
					*module = importDesc;
					return;
				}
			}
			++importDesc;
		}
	}
}

void hook_IAT_exec(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	PIMAGE_IMPORT_DESCRIPTOR importDesc;
	PIMAGE_IMPORT_BY_NAME IATImport;

	GetImportFromAddress(address, &importDesc, &IATImport);

	char* modName = (char*)((BYTE*)exec->imgBase + importDesc->Name);
	std::cout << "CALL " << modName << "->" << IATImport->Name << std::endl;
	print_emulator_cpu_state();

	if (em->breakOnImport)
		HandleUserInput();

	if (em->useCallbacks)
	{
		ImportCallback handler = em->GetCallback(IATImport->Name);
		if (handler)
		{
			uint64_t ret = (*handler)(uc);
			em->WriteReg(UC_X86_REG_RAX, &ret);
			if(!em->callstack.empty())
				em->callstack.pop_back();
		}
	}

	return;
}

void hook_jump_instruction(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	if (addressBlacklisted(address))
		return;

	LPVOID real_address = (LPVOID)((BYTE*)exec->imgBase + (address - exec->EmulationImageBase));
	ZydisDisassembledInstruction instruction;
	if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, address, real_address, 16, &instruction)))
	{
		ZydisMnemonic mnem = instruction.info.mnemonic;

		if (mnem >= ZYDIS_MNEMONIC_JB && mnem <= ZYDIS_MNEMONIC_JZ)
		{
			if (skip_first > 0)
			{
				skip_first--;
				return;
			}

			std::cout << std::endl << "+" << jump_count << std::endl;
			print_insn(&instruction);
			print_emulator_cpu_state();
		}
		if (mnem == ZYDIS_MNEMONIC_CALL)
		{
			std::cout << std::endl << "+" << jump_count << std::endl;
			em->PushCall(address);
			print_insn(&instruction);
			print_emulator_cpu_state();
		}
		else if (mnem == ZYDIS_MNEMONIC_RET)
			em->PopCall();

		if (isAddressBreakpoint(address) || em->step)
		{
			std::cout << std::endl << "+" << jump_count << std::endl;
			print_insn(&instruction);
			print_emulator_cpu_state();
			HandleUserInput();
		}
	}

}

void hook_jump_count(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
	LPVOID real_address = (LPVOID)((BYTE*)exec->imgBase + (address - exec->EmulationImageBase));
	ZydisDisassembledInstruction instruction;
	if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, address, real_address, 16, &instruction)))
	{
		ZydisMnemonic mnem = instruction.info.mnemonic;
		if (mnem == ZYDIS_MNEMONIC_JMP)
		{
			jump_count++;
		}
	}
}

void hook_memory(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data)
{
	uint64_t mem_value = 0x0;
	uint64_t r_rip;
	uc_reg_read(uc, UC_X86_REG_RIP, &r_rip);

	//Get Location of Address
	std::string location;
	em->GetAddressMapName(address, location);
	
	if (addressBlacklisted(r_rip))
		return;

	if (location == "Stack")
	{
		switch (type)
		{
		case UC_MEM_WRITE:
			std::cout << (LPVOID)r_rip << ":\tValue: " << (LPVOID)value << ":\tWritten To " << location << " Address: " << (LPVOID)address << "\tSize: " << (LPVOID)size << std::endl;
			break;
		case UC_MEM_READ:
			uc_mem_read(uc, address, &mem_value, size);
			std::cout << (LPVOID)r_rip << ":\tValue: " << (LPVOID)mem_value << ":\tRead from " << location << " Address: " << (LPVOID)address << "\tSize : " << (LPVOID)size << std::endl;
			break;
		case UC_MEM_FETCH:
			std::cout << (LPVOID)r_rip << ":\tValue: " << (LPVOID)value << ":\tFetched from " << location << " Address: " << (LPVOID)address << "\tSize: " << (LPVOID)size << std::endl;
			break;
		}
	}
	
}

void hook_custom_memory(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data)
{
	/*if (address >= param_1_driverObject && address <= param_2_registryPath + 0x8)
	{

	}*/
}

void hook_parameter_memory(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data)
{
	uint64_t mem_value = 0x0;
	uint64_t r_rip;
	uc_reg_read(uc, UC_X86_REG_RIP, &r_rip);
	std::string location;
	//Get Location of Address
	/*if (address >= param_1_driverObject && address <= param_2_registryPath + 0x8)
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
	}*/
}

void hook_invalid_memory(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data)
{
	uint64_t r_rip;
	uc_reg_read(uc, UC_X86_REG_RIP, &r_rip);
	std::cout << (LPVOID) r_rip << ":\tAccess Violation at Address: " << (LPVOID)address << "\tSize: " << (LPVOID)size << std::endl;
}

