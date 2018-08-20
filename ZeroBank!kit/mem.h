#pragma once


#define MI_POOL_COPY_BYTES 512
#define MI_MAPPED_COPY_PAGES 14

ULONG __stdcall KiExceptionInfo(IN PEXCEPTION_POINTERS ExceptionPointers,
	IN OUT PLOGICAL ExceptionAddressConfirmed,
	IN OUT PULONG_PTR BadVa);

NTSTATUS __stdcall KiCopyVirtualMemory(IN PEPROCESS Process1,
	IN PVOID Buffer1,
	IN PEPROCESS Process2,
	OUT PVOID Buffer2,
	IN SIZE_T BufferLength,
	IN KPROCESSOR_MODE Mode,
	OUT PSIZE_T ReturnSize);

NTSTATUS __stdcall MiDoPoolCopy(IN PEPROCESS Process1,
	IN PVOID Buffer1,
	IN PEPROCESS Process2,
	OUT PVOID Buffer2,
	IN SIZE_T BufferLength,
	IN KPROCESSOR_MODE Mode,
	OUT PSIZE_T ReturnSize);

NTSTATUS __stdcall MiDoMappedCopy(IN PEPROCESS Process1,
	IN PVOID Buffer1,
	IN PEPROCESS Process2,
	OUT PVOID Buffer2,
	IN SIZE_T BufferLength,
	IN KPROCESSOR_MODE Mode,
	OUT PSIZE_T ReturnSize);

PVOID __stdcall KiAllocateMappedVirtualMemory(IN ULONG Size,
	IN ULONG PoolTag,
	OUT PMDL *MdlAddress,
	IN PROOTKIT_API_HASH Hash);

VOID __stdcall KiFreeMappedVirtualMemory(IN PVOID MappedVirtualMemory,
	IN ULONG PoolTag,
	IN PMDL Address,
	IN PROOTKIT_API_HASH Hash);
