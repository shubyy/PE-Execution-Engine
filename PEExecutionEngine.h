#pragma once
#include <Windows.h>

uint64_t roundUp(uint64_t numToRound, uint64_t multiple)
{
    if (multiple == 0)
        return numToRound;

    int remainder = numToRound % multiple;
    if (remainder == 0)
        return numToRound;

    return numToRound + multiple - remainder;
}

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _DRIVER_OBJECT
{
    unsigned short Type;
    unsigned short Size;
    LPVOID DeviceObject;
    ULONG Flags;
    LPVOID DriverStart;
    ULONG DriverSize;
    LPVOID DriverSection;
    LPVOID DriverExtension;
    UNICODE_STRING DriverName;
    PUNICODE_STRING HardwareDatabase;
    LPVOID FastIoDispatch;
    LPVOID DriverInit;
    LPVOID DriverStartIo;
    LPVOID DriverUnload;
    LPVOID MajorFunction[28];
} DRIVER_OBJECT, *PDRIVER_OBJECT;


void AllocKernelSpecificRegions();