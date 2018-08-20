#include "server_globals.h"

void rc4_init(rc4_ctx *ctx, const uint8 *key, uint32 key_len)
{
	uint32 i;
	uint8 *s;
	uint8 t, tmp;

	t = 0;
	s = ctx->se;

	assert(key_len > 0 && key_len <= 256);

	ctx->pose = 1;
	ctx->posd = 1;
	ctx->te = 0;
	ctx->td = 0;

	memcpy(s, rc4_table, 256);

	for (i = 0; i < 256; i++) {
		t += s[i] + key[i % key_len];
		SWAP(s[i], s[t]);
	}

	memcpy(ctx->sd, s, 256);
}

void rc4_encrypt(rc4_ctx *ctx, const uint8 *src, uint8 *dst, uint32 len)
{
	uint32 i;
	uint32 pos;
	const uint8 *new_src;
	uint8 *s, *new_dst;
	uint8 t, tmp;

	pos = ctx->pose;
	s = ctx->se;
	t = ctx->te;

	new_src = src - pos;
	new_dst = dst - pos;

	for (i = pos; i < len + pos; i++) {
		RC4_CRYPT();
	}

	ctx->pose = i;
	ctx->te = t;
}

void rc4_decrypt(rc4_ctx *ctx, const uint8 *src, uint8 *dst, uint32 len)
{
	uint32 i;
	uint32 pos;
	const uint8 *new_src;
	uint8 *s, *new_dst;
	uint8 t, tmp;

	pos = ctx->posd;
	s = ctx->sd;
	t = ctx->td;

	new_src = src - pos;
	new_dst = dst - pos;

	for (i = pos; i < len + pos; i++) {
		RC4_CRYPT();
	}

	ctx->posd = i;
	ctx->td = t;
}


INT send_packet_encrypted(IN SOCKET sock,IN INT keytype, IN PVOID Buffer, IN INT len)
{
	PZEROBANK_PACKET_TYPE typeout = NULL;
	rc4_ctx ctx = { 0 };
	INT sendsize = 0;

	// allocate memory for output buffer

	typeout = (PZEROBANK_PACKET_TYPE)RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ZEROBANK_PACKET_TYPE));
	if (typeout != NULL)
	{
		// zero out the buffer

		RtlSecureZeroMemory(typeout, sizeof(ZEROBANK_PACKET_TYPE));

		// init rc4 context selecting key number previously

		switch (keytype)
		{
		case RC4_KEY_1:
			rc4_init(&ctx, key1, sizeof(key1));
			break;
		case RC4_KEY_2:
			rc4_init(&ctx, key2, sizeof(key2));
			break;
		case RC4_KEY_3:
			rc4_init(&ctx, key3, sizeof(key3));
			break;
		default:
			break;
		}

		// encrypt packet-buffer

		rc4_encrypt(&ctx, (const uint8*)Buffer, (uint8*)typeout, len);

		// send buffer

		sendsize = send(sock, (const char*)typeout, len, 0);
		if (sendsize <= 0)
			return 1;
	}

	// free previous allocated memory

	RtlFreeHeap(GetProcessHeap(), 0, typeout);

	return sendsize;
}


PVOID recv_decrypted(IN SOCKET sock, IN INT keytype, IN PVOID Alloc, IN ULONG NumberOfBytes)
{
	rc4_ctx ctx = { 0 };
	int offset = 0;
	int amount = 0;
	PVOID out = NULL;

	switch (keytype)
	{
	case RC4_KEY_1:
		rc4_init(&ctx, key1, sizeof(key1));
		break;
	case RC4_KEY_2:
		rc4_init(&ctx, key2, sizeof(key2));
		break;
	case RC4_KEY_3:
		rc4_init(&ctx, key3, sizeof(key3));
		break;
	default:
		break;
	}

	Alloc = RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, NumberOfBytes);
	if (Alloc == NULL)
		return 1;

	memset(Alloc, 0, NumberOfBytes);

	while (NumberOfBytes > offset)
	{
		amount = recv(sock, (char*)Alloc + offset, NumberOfBytes - offset, 0);
		if (amount <= 0)
			break;
		else
			offset += amount;
	}

	rc4_decrypt(&ctx, (const uint8*)Alloc, (uint8*)Alloc, NumberOfBytes);

	out = Alloc;

	return out;

}