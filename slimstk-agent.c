#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>

#include <sys/stat.h>
#include <sys/mman.h>

#include <openssl/bio.h>
#include <openssl/aes.h>
#include <openssl/pem.h>

#include "base64.h"

void
dump (void *buf, int n)
{
	int i;
	int j;
	int c;

	for (i = 0; i < n; i += 16) {
		printf ("%04x: ", i);
		for (j = 0; j < 16; j++) {
			if (i+j < n)
				printf ("%02x ", ((unsigned char *)buf)[i+j]);
			else
				printf ("   ");
		}
		printf ("  ");
		for (j = 0; j < 16; j++) {
			c = ((unsigned char *)buf)[i+j] & 0x7f;
			if (i+j >= n)
				putchar (' ');
			else if (c < ' ' || c == 0x7f)
				putchar ('.');
			else
				putchar (c);
		}
		printf ("\n");

	}
}

struct secbuf {
	unsigned char *buf;
	int avail;
	int used;
};


struct secmem {
	struct secbuf *id_rsa_cipher;
	struct secbuf *id_rsa_clear;
	struct secbuf *secmem_key;
	struct secbuf *secmem_iv;
};

void
usage (void)
{
	fprintf (stderr, "usage: slimstk-agent\n");
	exit (1);
}

void
urandom (void *buf, size_t size)
{
	static int urandom_fd;

	if (urandom_fd == 0) {
		if ((urandom_fd = open ("/dev/urandom", O_RDONLY)) < 0) {
			fprintf (stderr, "can't open /dev/urandom\n");
			exit (1);
		}
	}

	if (read (urandom_fd, buf, size) != size) {
		fprintf (stderr, "urandom read error\n");
		exit (1);
	}
}

unsigned int
urandom_uint (void)
{
	unsigned int val;
	urandom (&val, sizeof val);
	return (val);
}

void *
secure_malloc (int size) 
{
	int act_size;
	void *ret;

	act_size = urandom_uint () % (1000 * 1000);
	if (act_size < size)
		act_size += size * 10;
	if ((ret = malloc (act_size)) == NULL) {
		printf ("out of memory (%d)\n", act_size);
		exit (1);
	}

	if (mlock (ret, size) < 0) {
		printf ("error locking memory: %s\n", strerror (errno));
		exit (1);
	}

	urandom (ret, size);

	return (ret);
}

struct secbuf *
make_secbuf (size_t size)
{
	struct secbuf *sp;

	sp = secure_malloc (sizeof *sp);
	sp->buf = secure_malloc (size);
	sp->avail = size;
	sp->used = 0;

	return (sp);
}

void
wipe_privkey (struct secmem *secmem)
{
	memset (secmem->id_rsa_clear->buf, 0, secmem->id_rsa_clear->used);
	secmem->id_rsa_clear->used = 0;
}

void
encrypt_privkey (struct secmem *secmem)
{
	AES_KEY aes_key;
	int n, tail;
	int rc;

	memset (&aes_key, 0, sizeof aes_key);
	rc = AES_set_encrypt_key (secmem->secmem_key->buf,
				  secmem->secmem_key->avail * 8, 
				  &aes_key);
	if (rc != 0) {
		printf ("error setting aes key\n");
		exit (1);
	}
	n = secmem->id_rsa_clear->used;
	tail = n % 8;
	if (tail)
		n += 8 - tail;
	n = AES_wrap_key (&aes_key, secmem->secmem_iv->buf,
			  secmem->id_rsa_cipher->buf,
			  secmem->id_rsa_clear->buf, n);

	secmem->id_rsa_cipher->used = n;
	
	wipe_privkey (secmem);
}

void
decrypt_privkey (struct secmem *secmem)
{
	AES_KEY aes_key;
	int n;

	AES_set_decrypt_key (secmem->secmem_key->buf,
			     secmem->secmem_key->avail * 8, 
			     &aes_key);
	n = AES_unwrap_key (&aes_key, secmem->secmem_iv->buf,
			    secmem->id_rsa_clear->buf,
			    secmem->id_rsa_cipher->buf,
			    secmem->id_rsa_cipher->used);
	secmem->id_rsa_clear->used = n;
}

int
decrypt_file (struct secmem *secmem, char *encname, char *clearname)
{
	FILE *inf = NULL;
	char buf[1000];
	unsigned char filekey_cipher[1000];
	int filekey_cipher_len;
	int len;
	char *p;
	unsigned char iv[1000];
	int ivlen;
	char *user;
	BIO *bio = NULL;
	EVP_PKEY *pkey;
	unsigned char filekey[1000];
	int filekey_len;
	struct stat statb;
	int cipher_base64_avail;
	char *cipher_base64 = NULL;
	int cipher_bin_avail;
	int cipher_bin_used;
	unsigned char *cipher_bin = NULL;
	int clear_bin_avail;
	int clear_bin_used;
	unsigned char *clear_bin = NULL;
	int thistime;
	int offset, togo;
	int rc;
	int ret = 0;
	const int aeskey_size = 256 / 8;
	unsigned char aeskey[aeskey_size];
	EVP_CIPHER_CTX evp;
	FILE *outf = NULL;

	EVP_CIPHER_CTX_init (&evp);
			
	if ((user = getenv ("USER")) == NULL)
		goto bad;

	if ((inf = fopen (encname, "r")) == NULL)
		goto bad;

	while (fgets (buf, sizeof buf, inf) != NULL) {
		len = strlen (buf);
		while (len > 0 && isspace (buf[len-1]))
			buf[--len] = 0;
		if (buf[0] == 0)
			break;

		for (p = buf; *p && ! isspace (*p); p++)
			;
		if (*p)
			*p++ = 0;

		if (strcmp (buf, "-iv") == 0) {
			if ((ivlen = base64_decode (p, iv, sizeof iv - 1)) < 0)
				goto bad;
		} else if (strcmp (buf, user) == 0) {
			if ((filekey_cipher_len
			     = base64_decode (p, filekey_cipher,
					      sizeof filekey_cipher - 1)) < 0)
				goto bad;
		}

	}

	decrypt_privkey (secmem);

	bio = BIO_new_mem_buf (secmem->id_rsa_clear->buf,
			       secmem->id_rsa_clear->used);
	if ((pkey = PEM_read_bio_PrivateKey (bio, NULL, NULL, NULL)) == NULL) {
		fprintf (stderr, "error in PEM_read_bio_PrivateKey\n");
		goto bad;
	}

	filekey_len = RSA_private_decrypt (filekey_cipher_len, filekey_cipher,
					   filekey,
					   pkey->pkey.rsa,
					   RSA_PKCS1_PADDING);

	BIO_free_all (bio);
	bio = NULL;
	wipe_privkey (secmem);
	
	if (filekey_len < 0) {
		fprintf (stderr, "RSA_private_decrypt error %d\n",
			 filekey_len);
		goto bad;
	}
	printf ("filekey %d\n", filekey_len);
	dump (filekey, filekey_len);

	printf ("iv %d\n", ivlen);
	dump (iv, ivlen);

	fstat (fileno (inf), &statb);
	cipher_base64_avail = statb.st_size;
	if ((cipher_base64 = malloc (cipher_base64_avail + 1)) == NULL) {
		fprintf (stderr, "out of memory\n");
		exit (1);
	}
	
	thistime = fread (cipher_base64, 1, cipher_base64_avail, inf);
	cipher_base64[thistime] = 0;

	cipher_bin_avail = cipher_base64_avail; /* bigger than needed */
	if ((cipher_bin = malloc (cipher_bin_avail)) == NULL) {
		fprintf (stderr, "out of memory\n");
		exit (1);
	}

	cipher_bin_used = base64_decode (cipher_base64,
					 cipher_bin, cipher_bin_avail);

	/* EVP_DecryptUpdate needs a blocksize of extra space at the end */
	clear_bin_avail = cipher_bin_used + 100;
	if ((clear_bin = malloc (clear_bin_avail)) == NULL) {
		fprintf (stderr, "out of memory\n");
		exit (1);
	}

	if (filekey_len > aeskey_size) {
		fprintf (stderr, "bad filekey size %d\n", filekey_len);
		goto bad;
	}
	memcpy (aeskey, filekey, filekey_len);
	EVP_DecryptInit (&evp, EVP_aes_256_cbc(), aeskey, iv);

	offset = 0;
	togo = clear_bin_avail;

	thistime = clear_bin_avail;
	rc = EVP_DecryptUpdate (&evp,
				clear_bin + offset,
				&thistime,
				cipher_bin, cipher_bin_used);
	if (rc <= 0) {
		fprintf (stderr, "decrypt error\n");
		goto bad;
	}
	printf ("rc=%d\n", rc);

	offset += thistime;
	togo -= thistime;

	thistime = togo;
	rc = EVP_DecryptFinal (&evp, clear_bin + offset, &thistime);
	if (rc <= 0) {
		printf ("decrypt final error %d\n", rc);
		thistime = 0;
	}
	offset += thistime;
	togo -= thistime;

	clear_bin_used = offset;

	printf ("clear: %d\n", clear_bin_used);
	dump (clear_bin, clear_bin_used);

	if ((outf = fopen (clearname, "w")) == NULL) {
		fprintf (stderr, "can't create %s\n", clearname);
		goto bad;
	}
	fwrite (clear_bin, 1, clear_bin_used, outf);
	fclose (outf);

	goto done;

bad:
	ret = -1;

done:
	wipe_privkey (secmem);

	EVP_CIPHER_CTX_cleanup(&evp);
	
	if (clear_bin)
		free (clear_bin);
	if (cipher_bin)
		free (cipher_bin);
	if (cipher_base64)
		free (cipher_base64);
	if (bio)
		BIO_free_all (bio);
	if (inf)
		fclose (inf);
	return (ret);
}

int
main (int argc, char **argv)
{
	int c;
	char cmd[1000];
	FILE *inf;
	int n;
	struct secmem *secmem;

	while ((c = getopt (argc, argv, "")) != EOF) {
		switch (c) {
		default:
			usage ();
		}
	}

	if (optind != argc)
		usage ();

	secure_malloc (1);
	secmem = secure_malloc (sizeof *secmem);
	secmem->id_rsa_clear = make_secbuf (8192);
	secmem->id_rsa_cipher = make_secbuf (8192);
	secmem->secmem_key = make_secbuf (128 / 8);
	secmem->secmem_iv = make_secbuf (128 / 8);

	snprintf (cmd, sizeof cmd,
		  "openssl rsa -in %s/.ssh/id_rsa -outform PEM",
		 getenv ("HOME"));
	printf ("%s\n", cmd);
	if ((inf = popen (cmd, "r")) == NULL) {
		printf ("error running: %s\n", cmd);
		exit (1);
	}

	n = fread (secmem->id_rsa_clear->buf,
		   1, secmem->id_rsa_clear->avail - 1, inf);
	secmem->id_rsa_clear->buf[n] = 0;
	secmem->id_rsa_clear->used = n;
	pclose (inf);

	encrypt_privkey (secmem);

	decrypt_file (secmem, "/home/pace/csse/x.enc", "TMP.clear");

	return (0);
}
