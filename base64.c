#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "base64.h"

char const base64_chars[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";
char base64_rev[256];

int
base64_encode (void const *inbuf, int inlen, char *outbuf, int outlen)
{
	char const *in;
	int outoff;
	int idx;
	int in0, in1, in2;
	int pad;

	in = inbuf;

	idx = 0;
	pad = 0;
	outoff = 0;
	while (idx < inlen) {
		in0 = in[idx++];
		if (idx < inlen) {
			in1 = in[idx++];
			if (idx < inlen) {
				in2 = in[idx++];
			} else {
				in2 = 0;
				pad = 1;
			}
		} else {
			in1 = 0;
			in2 = 0;
			pad = 2;
		}
			
		if (outoff + 5 >= outlen)
			return (-1);

		outbuf[outoff] = base64_chars[(in0 >> 2) & 0x3f];
		outbuf[outoff+1] = base64_chars[((in0 << 4) & 0x30)
						| ((in1 >> 4) & 0x0f)];
		outbuf[outoff+2] = base64_chars[((in1 << 2) & 0x3c)
						| ((in2 >> 6) & 0x03)];
		outbuf[outoff+3] = base64_chars[in2 & 0x3f];
		
		if (pad) {
			if (pad == 2)
				outbuf[outoff+2] = '=';
			outbuf[outoff+3] = '=';
			outoff += 4;
			break;
		}

		outoff += 4;
	}

	outbuf[outoff] = 0;
	return (outoff);
}

int
base64_decode (char const *inbuf, void *outbuf, int outlen)
{
	int vidx;
	char const *p;
	unsigned char v[4], raw[4];
	char const *in;
	int outoff;
	unsigned char *outp;
	int c;

	for (vidx = 0, p = base64_chars; *p; vidx++, p++)
		base64_rev[*p & 0xff] = vidx;

	in = inbuf;
	outoff = 0;
	outp = outbuf;
	while (1) {
		vidx = 0;
		while (vidx < 4) {
			while (isspace (*in))
				in++;
			if (*in == 0)
				goto done;

			/* equal signs will translate to 0 */
			c = *in++ & 0xff;
			raw[vidx] = c;
			v[vidx] = base64_rev[c];
			vidx++;
		}

		if (outoff + 4 >= outlen)
			return (-1);

		outp[outoff++] = ((v[0] << 2) & 0xfc) | ((v[1] >> 4) & 0x03);
		if (raw[2] == '=')
			break;
		outp[outoff++] = ((v[1] << 4) & 0xf0) | ((v[2] >> 2) & 0x0f);
		if (raw[3] == '=')
			break;
		outp[outoff++] = ((v[2] << 6) & 0xc0) | (v[3] & 0x3f);
	}

done:
	outp[outoff] = 0;
	return (outoff);
}
