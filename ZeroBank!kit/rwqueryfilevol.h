#pragma once

NTSTATUS IopQueryFileInformation(IN HANDLE FileHandle,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS InfoClass);

NTSTATUS IopQueryVolumeInformationFile(IN HANDLE Handle,
	OUT PVOID VolumeInformation,
	IN ULONG Length,
	IN FS_INFORMATION_CLASS InfoClass);


NTSTATUS IopGetFileSize(IN HANDLE Handle,
	OUT PLARGE_INTEGER Size);


NTSTATUS IopReadFile(IN HANDLE handle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL);

NTSTATUS IopWriteFile(IN HANDLE Handle,
<<<<<<< HEAD
=======
	IN ACCESS_MASK DesiredAccess,
>>>>>>> adding files
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL);

NTSTATUS IopDeleteFile(IN PFILE_OBJECT socket,
	IN PCHAR FileName);