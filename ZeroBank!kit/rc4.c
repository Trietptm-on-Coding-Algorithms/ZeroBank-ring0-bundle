#include "common.h"

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

	kimemcpy(s, rc4_table, 256);

	for (i = 0; i < 256; i++) 
	{
		t += s[i] + key[i % key_len];
		SWAP_BYTES(s[i], s[t]);
	}

	kimemcpy(ctx->sd, s, 256);
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

	for (i = pos; i < len + pos; i++)
	{
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

	for (i = pos; i < len + pos; i++) 
	{
		RC4_CRYPT();
	}

	ctx->posd = i;
	ctx->td = t;
}