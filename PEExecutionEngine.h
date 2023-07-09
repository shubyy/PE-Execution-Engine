#pragma once
#include <Windows.h>

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

typedef struct _TIB
{
    LPVOID ExceptionList;
	LPVOID StackBase;
	LPVOID StackLimit;
	LPVOID SubSystemTib;
	LPVOID FiberData;
	LPVOID ArbitraryUserPointer;
	LPVOID Self;    
} TIB, *PTIB;

void AllocAndSetTIBBlock();
void AllocKernelSpecificRegions();
void InitialiseXMMRegs();