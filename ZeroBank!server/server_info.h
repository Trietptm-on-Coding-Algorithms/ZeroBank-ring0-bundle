#pragma once

typedef struct _ROOTKIT_SYS_INFORMATION
{
	unsigned long NumberOfDisks;
	unsigned long NumberOfFloppies;
	unsigned long NumberOfCdRoms;
	unsigned long NumberOfSerialPorts;
	unsigned long NumberOfParallelPorts;
	unsigned long TapeDrivesCount;
	unsigned long ScsiCount;
	unsigned short ActiveGroupCount;
	KAFFINITY ActiveProcessors;
	unsigned long ActiveProcessorsCount;
	unsigned long long InterruptTime;
	unsigned long MaximunProcessorCount;

}ROOTKIT_SYS_INFORMATION, *PROOTKIT_SYS_INFORMATION;

BOOLEAN rootkit_get_sys_information(IN SOCKET sock, IN BYTE PacketType);