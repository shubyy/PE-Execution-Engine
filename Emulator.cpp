#include "Emulator.h"
#include "EmulatorImportCallback.h"
#include <iostream>
#include "Executable.h"

Emulator(Executable* exec)
{
	init = false;
	step = false;
	breakOnImport = true;
	useCallbacks = true;
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

bool Emulator::AddMapping(uint64_t base_address, uint64_t size, uint32_t protect, const char *name)
{
	uc_err err = uc_mem_map(uc, base_address, size, protect);
	if (err == UC_ERR_OK)
	{
		EmulatorMap* map = new EmulatorMap(name, base_address, size, protect);
		std::cout << "Added Map: " << name << "\t" << (LPVOID)base_address << "-" << (LPVOID)(base_address + size) << std::endl;
		emulator_maps.push_back(map);
		return true;
	}
	std::cout << "uc err: " << err << std::endl;
	return false;
}

bool Emulator::AddMappingFromSource(uint64_t base_address, uint64_t map_size, void* source, uint64_t source_size, uint32_t protect, const char* name)
{
	if (map_size < source_size)
		return false;
		
	if (AddMapping(base_address, map_size, protect, name) && WriteEmuMem(base_address, source, source_size))
		return true;

	return false;
}

bool Emulator::WriteEmuMem(uint64_t base_address, void* source, uint64_t size)
{
	if (uc_mem_write(uc, base_address, source, size) != UC_ERR_OK)
		return false;

	return true;
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

void Emulator::PushCall(uint64_t call_address)
{
	callstack.push_back(call_address);
}

void Emulator::PopCall()
{
	callstack.pop_back();
}

bool Emulator::StartEmulation(uint64_t start, uint64_t end, uint64_t timeout, size_t count)
{
	uc_err err = uc_emu_start(uc, start, end, timeout, count);
	if (err != UC_ERR_OK)
		return false;

	return true;
}

void Emulator::hook_IAT_exec(uint64_t address, uint32_t size, void* user_data)
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
			em->callstack.pop_back();
		}
	}

	return;
}
