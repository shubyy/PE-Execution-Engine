#include "Emulator.h"
#include "EmulatorImportCallback.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include "Executable.h"


Emulator::Emulator(Executable* exec, EEmulatorType EmulatorType)
{
	init = false;
	step = false;
	breakOnImport = true;
	useCallbacks = true;
	breakOnRet = false;
	breakOnJump = false;
	this->exec = exec;
	type = EmulatorType;
	uc_mode mode = UC_MODE_64;
	switch (type)
	{
	case EMx32:
		mode = UC_MODE_32;
		break;
	case EMx64:
		mode = UC_MODE_64;
		break;
	};
	uc_err err = uc_open(UC_ARCH_X86, mode, &uc);
	if (err == UC_ERR_OK)
		init = true;

	RegisterEmulatorCallbacks(this);

}

EmulatorMap* Emulator::AddMapping(uint64_t base_address, uint64_t size, uint32_t protect, const char *name)
{
	uc_err err = uc_mem_map(uc, base_address, size, protect);

	if (err == UC_ERR_OK)
	{
		EmulatorMap* map = new EmulatorMap(name, base_address, size, protect);
		std::cout << "Added Map: " << name << "\t" << (LPVOID)base_address << "-" << (LPVOID)(base_address + size) << std::endl;
		emulator_maps.push_back(map);
		return map;
	}
	std::cout << "uc err: " << err << std::endl;
	return NULL;
}

void Emulator::RemoveMap(EmulatorMap* map)
{
	uc_mem_unmap(uc, map->m_map_start, map->m_map_size);
	emulator_maps.remove(map);
	delete map;
}

EmulatorMap* Emulator::AddMappingFromSource(uint64_t base_address, uint64_t map_size, void* source, uint64_t source_size, uint32_t protect, const char* name)
{
	EmulatorMap* map = NULL;
	if (map_size < source_size)
		return NULL;
	
	if ((map = AddMapping(base_address, map_size, protect, name)) != NULL && WriteEmuMem(base_address, source, source_size))
		return map;

	return NULL;
}

EmulatorMap* Emulator::AddExistingMapping(uint64_t base_address, void* source, uint64_t source_size, uint32_t protect, const char* name)
{
	uc_err err = uc_mem_map_ptr(uc, base_address, source_size, protect, source);

	if (err == UC_ERR_OK)
	{
		EmulatorMap* map = new EmulatorMap(name, base_address, source_size, protect);
		std::cout << "Added Map: " << name << "\t" << (LPVOID)base_address << "-" << (LPVOID)(base_address + source_size) << std::endl;
		emulator_maps.push_back(map);
		return map;
	}
	std::cout << "uc err: " << err << std::endl;
	return NULL;
}

bool Emulator::WriteEmuMem(uint64_t base_address, void* source, uint64_t size)
{
	if (uc_mem_write(uc, base_address, source, size) != UC_ERR_OK)
		return false;

	return true;
}

EmulatorMap* Emulator::GetMapFromName(const char* name)
{
	for (auto *map : emulator_maps)
	{
		if (strcmp(map->map_name, name) == 0)
			return map;
	}

	return NULL;
}

void Emulator::RegisterCallback(std::string name, ImportCallback callback)
{
	callbacks.emplace(name, callback);
}

void Emulator::GetAddressMapName(uint64_t address, std::string& name)
{
	for(auto map : emulator_maps)
	{
		if (address >= map->m_map_start && address < (map->m_map_start + map->m_map_size))
		{
			name = map->map_name;
			return;
		}
	}

	name = "Unknown";
}

ImportCallback Emulator::GetCallback(std::string name)
{
	std::unordered_map<std::string, ImportCallback>::iterator itr = callbacks.find(name);
	if (itr != callbacks.end())
		return itr->second;

	return NULL;
}

bool Emulator::WriteMSR(uint64_t reg, uint64_t value)
{
	uint64_t orax;
	uint64_t ordx;
	uint64_t orcx;
	ReadReg(UC_X86_REG_RAX, &orax);
	ReadReg(UC_X86_REG_RAX, &ordx);
	ReadReg(UC_X86_REG_RAX, &orcx);

	//x86: wrmsr
	byte buf[] = { 0x0f, 0x30 };
	uint64_t scratch = 0x1000;
	EmulatorMap *wrmap = AddMappingFromSource(scratch, 0x1000, buf, sizeof(buf), UC_PROT_ALL, "msr_write");

	uint64_t irax = value & 0xFFFFFFFF;
	uint64_t irdx = (value >> 32) & 0xFFFFFFFF;
	uint64_t ircx = reg & 0xFFFFFFFF;
	WriteReg(UC_X86_REG_RAX, &irax);
	WriteReg(UC_X86_REG_RDX, &irdx);
	WriteReg(UC_X86_REG_RCX, &ircx);

	//Run wrmsr instruction
	bool success = StartEmulation(scratch, scratch + sizeof(buf), 100, 1);

	WriteReg(UC_X86_REG_RAX, &orax);
	WriteReg(UC_X86_REG_RDX, &ordx);
	WriteReg(UC_X86_REG_RCX, &orcx);

	RemoveMap(wrmap);
	return success;
}

void Emulator::PushCall(uint64_t call_address)
{
	callstack.push_back(call_address);
}

void Emulator::PopCall()
{
	callstack.pop_back();
}

bool Emulator::IsAddressBreakpoint(uint64_t address)
{
	for (uint64_t bp : emulator_breakpoints)
		if (bp == address || step)
			return true;

	return false;
}

bool Emulator::StartEmulation(uint64_t start, uint64_t end, uint64_t timeout, size_t count)
{
	uc_err err = uc_emu_start(uc, start, end, timeout, count);
	if (err != UC_ERR_OK)
		return false;

	return true;
}

void Emulator::HandleUserInput()
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
		else if (input[0] == 'b')
		{
			if (input[1] == 'e')
			{
				breakOnImport = !breakOnImport;
				std::cout << "Break on Export:  " << (LPVOID)breakOnImport << std::endl;
				continue;
			}

			if (input[1] == 'j')
			{
				breakOnJump = !breakOnJump;
				std::cout << "Break on Jump:  " << (LPVOID)breakOnImport << std::endl;
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
				bpAddress = exec->convertFromPreferredModuleBase(address);
			}

			AddBreakpoint(bpAddress);
			std::cout << "Added Breakpoint: " << (LPVOID)bpAddress << std::endl;
		}
		else if (input == "rb")
		{
			std::cout << "Enter Index: ";

			std::string str_index;
			std::cin >> str_index;
			int index = std::stoi(str_index);

			if (index >= emulator_breakpoints.size())
			{
				std::cout << "Invalid Index" << std::endl;
				continue;
			}

			std::vector<uint64_t>::iterator it = emulator_breakpoints.begin();
			std::advance(it, index);
			std::cout << "Removing Breakpoint: " << (LPVOID)*it << std::endl;
			emulator_breakpoints.erase(it);
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

			WriteReg(UC_X86_REG_RAX, &value);
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
			std::cout << "Enter count: ";
			std::string count_string;
			std::cin >> count_string;

			int count = std::stoi(count_string);
			uint64_t size = std::stoull(size_string);
			for (int i = 0; i < count; i++)
				print_memory(address + i * size, size);

		}
		else if (input == "dump")
		{
			std::cout << "Enter Dump file name: ";
			std::string fileName;
			std::cin >> fileName;
			bool dumped = exec->DumpExecutable(fileName);
			if(dumped)
				std::cout << "Dumped to: " << fileName << std::endl;
			else
				std::cout << "Failed to dump" << std::endl;
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

void Emulator::print_memory(uint64_t address, size_t size)
{
	uint8_t* val = (uint8_t*)malloc(size);
	if (uc_mem_read(uc, address, val, size) == UC_ERR_OK)
		std::cout << (LPVOID)address << ": " << hexStr(val, size) << std::endl;
}

void Emulator::print_call_stack()
{
	unsigned int callstack_size = (unsigned int) callstack.size();
	for (unsigned int i = callstack_size - 1; i >= 0; --i)
		print_insn_at(callstack[i]);
}

void Emulator::print_insn(ZydisDisassembledInstruction* instruction)
{
	std::cout << (LPVOID)instruction->runtime_address << "\t" << instruction->text << std::endl;
}

void Emulator::print_insn_at(uint64_t address)
{
	LPVOID real_address = (LPVOID)((BYTE*)exec->imgBase + (address - exec->EmulationImageBase));
	ZydisDisassembledInstruction instruction;
	if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, address, real_address, 16, &instruction)))
		print_insn(&instruction);
}

void Emulator::print_emulator_cpu_state()
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
	std::cout << std::hex << " R8: 0x" << r_r8 << "  R9: 0x" << r_r9 << " R10: 0x" << r_r10 << " R11: 0x" << r_r11 << std::endl;
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

std::string hexStr(const uint8_t* data, size_t len)
{
	std::stringstream ss;
	ss << std::hex;

	for (int i = len - 1; i >= 0; i--)
		ss << std::setw(2) << std::setfill('0') << (int)data[i];

	return ss.str();
}