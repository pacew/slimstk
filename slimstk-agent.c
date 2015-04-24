#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <openssl/bio.h>
#include <openssl/aes.h>
#include <openssl/pem.h>

#include "base64.h"

#define KEYSIZE_BITS 256
#define KEYSIZE_BYTES (KEYSIZE_BITS / 8)
#define CIPHER_ALGO() (EVP_aes_256_cbc())
#define CIPHER_BLOCK_SIZE AES_BLOCK_SIZE

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

void setup_server (struct secmem *secmem);
void process_client (struct secmem *secmem, int sock);

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
	int before, after, total;
	void *base, *ret;

	before = urandom_uint () % (200 * 1000);
	before &= ~0xfff;
	after = urandom_uint () % (200 * 1000);
	total = before + size + after;

	if ((base = malloc (total)) == NULL) {
		fprintf (stderr, "out of memory (%d)\n", total);
		exit (1);
	}

	ret = base + before;

	if (mlock (ret, size) < 0) {
		fprintf (stderr, "error locking memory: %s\n",
			 strerror (errno));
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
	memset (secmem->id_rsa_clear->buf, 0, secmem->id_rsa_clear->avail);
}

void
encrypt_privkey (struct secmem *secmem)
{
	AES_KEY aes_key;
	int rc;

	memset (&aes_key, 0, sizeof aes_key);
	rc = AES_set_encrypt_key (secmem->secmem_key->buf,
				  secmem->secmem_key->avail * 8, 
				  &aes_key);
	if (rc != 0) {
		fprintf (stderr, "error setting aes key\n");
		exit (1);
	}

	/* size must be multiple of AES_BLOCK_SIZE */
	secmem->id_rsa_cipher->used
		= AES_wrap_key (&aes_key,
				secmem->secmem_iv->buf,
				secmem->id_rsa_cipher->buf,
				secmem->id_rsa_clear->buf,
				secmem->id_rsa_clear->used);

	wipe_privkey (secmem);
}

void
decrypt_privkey (struct secmem *secmem)
{
	AES_KEY aes_key;

	AES_set_decrypt_key (secmem->secmem_key->buf,
			     secmem->secmem_key->avail * 8, 
			     &aes_key);
	secmem->id_rsa_clear->used
		= AES_unwrap_key (&aes_key,
				  secmem->secmem_iv->buf,
				  secmem->id_rsa_clear->buf,
				  secmem->id_rsa_cipher->buf,
				  secmem->id_rsa_cipher->used);
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
	unsigned char aeskey[KEYSIZE_BYTES];
	EVP_CIPHER_CTX evp;
	FILE *outf = NULL;

	EVP_CIPHER_CTX_init (&evp);
			
	if ((user = getenv ("USER")) == NULL)
		goto bad;

	if ((inf = fopen (encname, "r")) == NULL) {
		fprintf (stderr, "can't open ciphertext %s\n", encname);
		goto bad;
	}

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

	if (filekey_len > KEYSIZE_BYTES) {
		fprintf (stderr, "bad filekey size %d\n", filekey_len);
		goto bad;
	}
	memcpy (aeskey, filekey, filekey_len);
	EVP_DecryptInit (&evp, CIPHER_ALGO(), aeskey, iv);

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
		fprintf (stderr, "decrypt final error %d\n", rc);
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
	FILE *inf;
	int n;
	struct secmem *secmem;
	char *p;
	int nblocks;
	int clear_size, clear_size_extra;
	char fname[1000];
	EVP_PKEY *pkey;
	BIO *bio;
	int rc;

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
	secmem->secmem_key = make_secbuf (KEYSIZE_BYTES);
	secmem->secmem_iv = make_secbuf (CIPHER_BLOCK_SIZE);

	snprintf (fname, sizeof fname, "%s/.ssh/id_rsa", getenv ("HOME"));
	if ((inf = fopen (fname, "r")) == NULL) {
		printf ("can't open %s\n", fname);
		exit (1);
	}

	OpenSSL_add_all_ciphers ();

	pkey = NULL;
	pkey = PEM_read_PrivateKey(inf, &pkey, NULL, NULL);
	if (pkey == NULL) {
		fprintf (stderr, "error getting private key\n");
		exit (1);
	}
	printf ("pkey %p\n", pkey);

	bio = BIO_new (BIO_s_mem ());
	printf ("bio %p\n", bio);

	rc = PEM_write_bio_PKCS8PrivateKey (bio, pkey,
					    NULL, NULL, 0, NULL, NULL);
	if (rc <= 0) {
		fprintf (stderr, "error setting up private key\n");
		exit (1);
	}

	n = BIO_get_mem_data (bio, &p);

	nblocks = (n + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
	clear_size = nblocks * AES_BLOCK_SIZE;
	clear_size_extra = clear_size + AES_BLOCK_SIZE;

	secmem->id_rsa_clear = make_secbuf (clear_size_extra);
	memset (secmem->id_rsa_clear->buf, 0, clear_size_extra);
	memcpy (secmem->id_rsa_clear->buf, p, n);
	secmem->id_rsa_clear->used = clear_size;

	secmem->id_rsa_cipher = make_secbuf (clear_size_extra);

	encrypt_privkey (secmem);

	setup_server (secmem);

	return (0);
}

void
setup_server (struct secmem *secmem)
{
	int listen_sock;
	struct sockaddr_un addr;
	int addrlen;
	int sock;
	int iflag;

	if ((listen_sock = socket (AF_UNIX, SOCK_STREAM, 0)) < 0) {
		fprintf (stderr, "can't create sock\n");
		exit (1);
	}

	memset (&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	addr.sun_path[0] = 0;
	sprintf (addr.sun_path + 1, "slimtstk-agent-%d", getuid ());
	addrlen = sizeof addr;

	if (bind (listen_sock, (struct sockaddr *)&addr, addrlen) < 0) {
		fprintf (stderr, "bind error: %s\n", strerror (errno));
		exit (1);
	}

	iflag = 1;
	setsockopt (listen_sock, SOL_SOCKET, SO_PASSCRED,
		    &iflag, sizeof iflag);

	if (listen (listen_sock, 5) < 0) {
		fprintf (stderr, "listen error: %s\n", strerror (errno));
		exit (1);
	}

	while (1) {
		printf ("await connection\n");
		if ((sock = accept (listen_sock, NULL, NULL)) < 0) {
			fprintf (stderr, "accept error: %s\n",
				 strerror (errno));
			exit (1);
		}

		printf ("accept ok %d\n", sock);
		process_client (secmem, sock);
		close (sock);
	}
}


void
process_client (struct secmem *secmem, int sock)
{
	char rpkt[5000];
	struct iovec iov;
	struct msghdr hdr;
	char aux[5000];
	int rpkt_len;
	struct cmsghdr *cmsg;
	struct ucred ucred;
	int ucred_valid;
	char *p;
	char *inname, *outname;
	char resp[1000];
	int len;

	*resp = 0;

	iov.iov_base = rpkt;
	iov.iov_len = sizeof rpkt - 1;

	memset (&hdr, 0, sizeof hdr);
	hdr.msg_iov = &iov;
	hdr.msg_iovlen = 1;
	hdr.msg_control = aux;
	hdr.msg_controllen = sizeof aux;
	hdr.msg_flags = 0;
		
	printf ("await message\n");
	rpkt_len = recvmsg (sock, &hdr, 0);
	if (rpkt_len < 0) {
		sprintf (resp, "recvmsg error: %s\n", strerror (errno));
		goto done;
	}

	printf ("recvmsg: %d\n", rpkt_len);
	rpkt[rpkt_len] = 0;

	printf ("iov_len %d\n", (int)iov.iov_len);
	dump (rpkt, rpkt_len);
	printf ("controllen %d\n", (int)hdr.msg_controllen);
	dump (hdr.msg_control, hdr.msg_controllen);
		
	ucred_valid = 0;
	for (cmsg = CMSG_FIRSTHDR (&hdr);
	     cmsg;
	     cmsg = CMSG_NXTHDR (&hdr, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET
		    && cmsg->cmsg_type == SCM_CREDENTIALS) {
			memcpy (&ucred, CMSG_DATA(cmsg), sizeof ucred);
			ucred_valid = 1;
		} else {
			printf ("unknown cmsg %d %d\n",
				cmsg->cmsg_level, cmsg->cmsg_type);
		}
	}

	if (! ucred_valid) {
		sprintf (resp, "can't find credentials\n");
		goto done;
	}

	printf ("request is from uid %d pid %d\n", ucred.uid, ucred.pid);

	if (ucred.uid != geteuid ()) {
		sprintf (resp, "invalid request from uid %d\n", ucred.uid);
		goto done;
	}

	p = rpkt;
	inname = p;
	if ((p = memchr (p, 0, rpkt_len)) == NULL) {
		sprintf (resp, "can't parse pkt");
		goto done;
	}
	p++;
	outname = p;

	printf ("inname %s\n", inname);
	printf ("outname %s\n", outname);

	if (inname[0] != '/' || outname[0] != '/') {
		sprintf (resp, "must use absolute paths");
		goto done;
	}

	printf ("decrypting...\n");
	if (decrypt_file (secmem, inname, outname) < 0) {
		sprintf (resp, "decrypt error\n");
		goto done;
	}
	sprintf (resp, "ok");

done:
	if (*resp == 0)
		sprintf (resp, "unknown error");
	len = strlen (resp);
	while (len > 0 && isspace (resp[len-1]))
		resp[--len] = 0;
	printf ("response: %s\n", resp);
	write (sock, resp, strlen (resp));
}

