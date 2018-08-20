#pragma once

#define 	GET_32BIT_LSB_FIRST(cp) (((UINT32)(unsigned char)(cp)[0]) | \
     ((UINT32)(unsigned char)(cp)[1] << 8 ) | \
     ((UINT32)(unsigned char)(cp)[2] << 16) | \
     ((UINT32)(unsigned char)(cp)[3] << 24))

#define 	PUT_32BIT_LSB_FIRST(cp, value) do { \
        (cp)[0] = (value) & 0xFF; \
        (cp)[1] = ((value) >> 8)  & 0xFF; \
        (cp)[2] = ((value) >> 16) & 0xFF; \
        (cp)[3] = ((value) >> 24) & 0xFF; \
	    } while(0)

#define 	F1(x, y, z)   (z ^ (x & (y ^ z)))
#define 	F2(x, y, z)   F1(z, x, y)
#define 	F3(x, y, z)   (x ^ y ^ z)
#define 	F4(x, y, z)   (y ^ (x | ~z))
#define 	MD5STEP(f, w, x, y, z, data, s)   ( w += f(x, y, z) + data, w = w<<s | w>>(32-s), w += x )

typedef struct _MD5Context
{
	UINT32 buf[4];
	UINT32 bits[2];
	unsigned char in[64];
} MD5Context;

void MD5Init(MD5Context *ctx);
void MD5Update(MD5Context *ctx, unsigned char const *buf, UINT32 len);
void MD5Final(unsigned char digest[16],MD5Context *ctx);
void MD5Transform(UINT32 buf[4], const unsigned char inext[64]);