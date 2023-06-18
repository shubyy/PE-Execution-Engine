#pragma once
#include "unicorn/unicorn.h"
#include "Zydis/Zydis.h"
#include <vector>
#include <unordered_map>
#include <string>
#include <optional>

class Executable;

enum EEmulatorType
{
	EMx32,
	EMx64
};

typedef std::optional<uint64_t> (*ImportCallback)(uc_engine *uc);

class EmulatorMap
{
public:
    char map_name[32];
    uint64_t m_map_start;
    uint64_t m_map_size;
    uint32_t m_protect;

    EmulatorMap(const char* name, uint64_t map_start, uint64_t map_size, uint32_t protect)
    {
        m_map_start = map_start;
        m_map_size = map_size;
        m_protect = protect;
        strncpy_s(map_name, name, 32);
    }
};

class Emulator
{
public:
    uc_engine *uc;
    Executable* exec;
    EEmulatorType type;

    std::vector<uint64_t> emulator_breakpoints;
    std::vector<EmulatorMap*> emulator_maps;
    std::vector<uint64_t> callstack;
    std::unordered_map<std::string, ImportCallback> callbacks;
    
    bool init;
    bool step;
    bool breakOnImport;
    bool useCallbacks;

    Emulator(Executable* exec, EEmulatorType EmulatorType);

    bool AddMapping(uint64_t base_address, uint64_t size, uint32_t protect, const char* name);

    bool AddMappingFromSource(uint64_t base_address, uint64_t map_size, void* source, uint64_t source_size, uint32_t protect, const char* name);

    bool AddExistingMapping(uint64_t base_address, void* source, uint64_t source_size, uint32_t protect, const char* name);

    bool WriteEmuMem(uint64_t base_address, void* source, uint64_t size);

    bool StartEmulation(uint64_t start, uint64_t end, uint64_t timeout, size_t count);

    void RegisterCallback(std::string name, ImportCallback callback);

    void GetAddressMapName(uint64_t address, std::string& name);

    void HandleUserInput();

    void print_memory(uint64_t address, size_t size);

    void print_call_stack();

    void print_insn(ZydisDisassembledInstruction* instruction);

    void print_insn_at(uint64_t address);

    void print_emulator_cpu_state();

    void PushCall(uint64_t call_address);
    void PopCall();

    bool IsAddressBreakpoint(uint64_t address);

    ImportCallback GetCallback(std::string name);

    void WriteReg(int reg, void* value)
    {
        uc_reg_write(uc, reg, value);
    }

    void ReadReg(int reg, void *value)
    {
        uc_reg_read(uc, reg, value);
    }

    void AddBreakpoint(uint64_t address)
    {
        emulator_breakpoints.push_back(address);
    }
};


std::string hexStr(const uint8_t* data, size_t len);