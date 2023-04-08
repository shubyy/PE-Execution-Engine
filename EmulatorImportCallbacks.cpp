#include "EmulatorImportCallback.h"
#include "Emulator.h"
#include <optional>
#include <Windows.h>
#include <iostream>

#define STATUS_SUCCESS 0

std::optional<uint64_t> _RtlWriteRegistryValue(uc_engine* uc)
{
	return STATUS_SUCCESS;
}

std::optional<uint64_t> _ZwOpenKey(uc_engine* uc)
{
	return STATUS_SUCCESS;
}

std::optional<uint64_t> _ZwFlushKey(uc_engine* uc)
{
	return STATUS_SUCCESS;
}

std::optional<uint64_t> _ZwClose(uc_engine* uc)
{
	return STATUS_SUCCESS;
}

void RegisterEmulatorCallbacks(Emulator *em)
{
	em->RegisterCallback("RtlWriteRegistryValue", &_RtlWriteRegistryValue);
	em->RegisterCallback("ZwOpenKey", &_ZwOpenKey);
	em->RegisterCallback("ZwFlushKey", &_ZwFlushKey);
	em->RegisterCallback("ZwClose", &_ZwClose);
}


