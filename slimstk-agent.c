#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <openssl/bio.h>
#include <openssl/aes.h>
#include <openssl/pem.h>

#include "base64.h"

int verbose;
int background_mode;
int kill_flag;

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
void run_server (struct secmem *secmem);
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
decrypt_file (struct secmem *secmem, char *encname,
	      char *errbuf, int errlen,
	      unsigned char **result_data, int *result_len)
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
	EVP_CIPHER_CTX evp;

	*result_data = NULL;
	*result_len = 0;

	errbuf[0] = 0;
	

	EVP_CIPHER_CTX_init (&evp);
			

	if ((user = getenv ("USER")) == NULL) {
		snprintf (errbuf, errlen, "can't find USER in env");
		goto bad;
	}

	if ((inf = fopen (encname, "r")) == NULL) {
		snprintf (errbuf, errlen, "can't open ciphertext %s", encname);
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
			if ((ivlen = base64_decode(p, iv, sizeof iv - 1)) < 0){
				snprintf (errbuf, errlen,
					  "base64 decode error for iv");
				goto bad;
			}
		} else if (strcmp (buf, user) == 0) {
			if ((filekey_cipher_len
			     = base64_decode (p, filekey_cipher,
					      sizeof filekey_cipher - 1)) < 0){
				snprintf (errbuf, errlen,
					  "bse64 decode error for filekey");
				goto bad;
			}
		}
		
	}
	
	decrypt_privkey (secmem);

	bio = BIO_new_mem_buf (secmem->id_rsa_clear->buf,
			       secmem->id_rsa_clear->used);
	if ((pkey = PEM_read_bio_PrivateKey (bio, NULL, NULL, NULL)) == NULL) {
		snprintf (errbuf, errlen, "error parsing private key");
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
		snprintf (errbuf, errlen, "error decrypting private key %d\n",
			  filekey_len);
		goto bad;
	}

	if (filekey_len != KEYSIZE_BYTES) {
		snprintf (errbuf, errlen, "invalid filekey size %d (want %d)\n",
			  filekey_len, KEYSIZE_BYTES);
		goto bad;
	}

	if (ivlen != CIPHER_BLOCK_SIZE) {
		snprintf (errbuf, errlen, "invalid size %d (want %d)\n",
			  ivlen, CIPHER_BLOCK_SIZE);
		goto bad;
	}

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

	if (cipher_bin_used < 0) {
		snprintf (errbuf, errlen,
			  "base64 decode error for main ciphertext");
		goto bad;
	}

	/* EVP_DecryptUpdate needs a blocksize of extra space at the end */
	clear_bin_avail = cipher_bin_used + CIPHER_BLOCK_SIZE;
	if ((clear_bin = malloc (clear_bin_avail)) == NULL) {
		fprintf (stderr, "out of memory\n");
		exit (1);
	}

	EVP_DecryptInit (&evp, CIPHER_ALGO(), filekey, iv);

	offset = 0;
	togo = clear_bin_avail;

	thistime = clear_bin_avail;
	rc = EVP_DecryptUpdate (&evp,
				clear_bin + offset,
				&thistime,
				cipher_bin, cipher_bin_used);
	if (rc <= 0) {
		snprintf (errbuf, errlen, "error decrypting file");
		goto bad;
	}

	offset += thistime;
	togo -= thistime;

	thistime = togo;
	rc = EVP_DecryptFinal (&evp, clear_bin + offset, &thistime);
	if (rc <= 0) {
		snprintf (errbuf, errlen, "error decrypting file 2");
		goto bad;
	}
	offset += thistime;
	togo -= thistime;

	clear_bin_used = offset;

	goto done;

bad:
	ret = -1;

done:
	wipe_privkey (secmem);

	EVP_CIPHER_CTX_cleanup(&evp);
	
	if (cipher_bin)
		free (cipher_bin);
	if (cipher_base64)
		free (cipher_base64);
	if (bio)
		BIO_free_all (bio);
	if (inf)
		fclose (inf);

	*result_data = clear_bin;
	*result_len = clear_bin_used;

	return (ret);
}

void
daemonize (void)
{
	int pid;
	int fd;
	
	fflush (stdout);
	fflush (stderr);
	
	if ((pid = fork ()) < 0) {
		perror ("fork");
		exit (1);
	}
	
	if (pid > 0) {
		/* let the child run a little before we exit */
		usleep (500 * 1000);
		exit (0);
	}
	
	setsid ();
	
	if ((fd = open ("/dev/null", O_RDWR)) >= 0) {
		if (fd != 0) {
			dup2 (fd, 0);
			dup2 (fd, 1);
			dup2 (fd, 2);
			close (fd);
		}
	}
}

int
kill_agent (void)
{
	int sock;
	struct sockaddr_un server_addr;
	int server_addrlen;
	

	sock = socket (AF_UNIX, SOCK_STREAM, 0);

	memset (&server_addr, 0, sizeof server_addr);
	server_addr.sun_family = AF_UNIX;
	server_addr.sun_path[0] = 0;
	sprintf (server_addr.sun_path + 1, "slimtstk-agent-%d", getuid ());
	server_addrlen = sizeof server_addr;
	
	if (connect (sock, (struct sockaddr *)&server_addr,
		     server_addrlen) < 0) {
		return (-1);
	}

	close (sock);
	return (0);
}

int lifetime_secs = 3600;

void
alarm_handler (int sig)
{
	exit (0);
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

	while ((c = getopt (argc, argv, "vbk")) != EOF) {
		switch (c) {
		case 'v':
			verbose = 1;
			break;
		case 'b':
			background_mode = 1;
			break;
		case 'k':
			kill_flag = 1;
			break;
		default:
			usage ();
		}
	}

	if (optind != argc)
		usage ();

	if (kill_flag) {
		if (kill_agent () < 0)
			exit (1);
		exit (0);
	}

	secure_malloc (1);
	secmem = secure_malloc (sizeof *secmem);
	secmem->secmem_key = make_secbuf (KEYSIZE_BYTES);
	secmem->secmem_iv = make_secbuf (CIPHER_BLOCK_SIZE);

	setup_server (secmem);

	snprintf (fname, sizeof fname, "%s/.ssh/id_rsa", getenv ("HOME"));
	if ((inf = fopen (fname, "r")) == NULL) {
		printf ("can't open %s\n", fname);
		exit (1);
	}

	OpenSSL_add_all_ciphers ();

	pkey = NULL;
	pkey = PEM_read_PrivateKey(inf, &pkey, NULL, NULL);
	if (pkey == NULL) {
		fprintf (stderr, "error parsing ssh private key\n");
		exit (1);
	}

	bio = BIO_new (BIO_s_mem ());

	rc = PEM_write_bio_PKCS8PrivateKey (bio, pkey,
					    NULL, NULL, 0, NULL, NULL);
	if (rc <= 0) {
		fprintf (stderr, "error preparing ssh private key\n");
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

	EVP_PKEY_free (pkey);
	pkey = NULL;

	BIO_free_all (bio);
	bio = NULL;


	if (background_mode)
		daemonize ();

	signal (SIGPIPE, SIG_IGN);

	signal (SIGALRM, alarm_handler);

	run_server (secmem);

	return (0);
}

int listen_sock;

void
setup_server (struct secmem *secmem)
{
	struct sockaddr_un addr;
	int addrlen;
	int iflag;

	if ((listen_sock = socket (AF_UNIX, SOCK_STREAM, 0)) < 0) {
		fprintf (stderr, "can't create socket for agent\n");
		exit (1);
	}

	memset (&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	addr.sun_path[0] = 0;
	sprintf (addr.sun_path + 1, "slimtstk-agent-%d", getuid ());
	addrlen = sizeof addr;

	if (bind (listen_sock, (struct sockaddr *)&addr, addrlen) < 0) {
		if (errno == EADDRINUSE && background_mode) {
			exit (0);
		}
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
}

void
run_server (struct secmem *secmem)
{
	int sock;

	while (1) {
		alarm (lifetime_secs);

		if (verbose)
			printf ("await connection\n");

		if ((sock = accept (listen_sock, NULL, NULL)) < 0) {
			fprintf (stderr, "accept error: %s\n",
				 strerror (errno));
			exit (1);
		}

		if (verbose)
			printf ("accept ok %d\n", sock);

		process_client (secmem, sock);
		close (sock);
	}
}


void
process_client (struct secmem *secmem, int sock)
{
	char rpkt[5000];
	int rpkt_len;
	struct ucred ucred;
	socklen_t slen;
	char *inname;
	int len;
	char errbuf[1000];
	unsigned char *result_data;
	int result_len;
	int off, togo, thistime;
	char *p;

	errbuf[0] = 0;

	slen = sizeof ucred;
	if (getsockopt (sock, SOL_SOCKET, SO_PEERCRED, &ucred, &slen) < 0) {
		snprintf (errbuf, sizeof errbuf,
			  "error getting credentials: %s",
			 strerror (errno));
		goto done;
	}

	if (verbose) {
		printf ("request is from uid %d pid %d\n",
			ucred.uid, ucred.pid);
	}

	if (ucred.uid != geteuid ()) {
		snprintf (errbuf, sizeof errbuf,
			  "invalid request from uid %d\n", ucred.uid);
		goto done;
	}

	if (verbose)
		printf ("read message\n");

	if ((rpkt_len = recv (sock, rpkt, sizeof rpkt - 1, 0)) < 0) {
		snprintf (errbuf, sizeof errbuf,
			  "recv error: %s\n", strerror (errno));
		goto done;
	}

	rpkt[rpkt_len] = 0;

	if (verbose) {
		printf ("recvmsg: %d\n", rpkt_len);
	}

	if (rpkt_len == 0)
		exit (0);

	inname = rpkt;

	if (verbose) {
		printf ("inname %s\n", inname);
	}

	if (inname[0] != '/') {
		snprintf (errbuf, sizeof errbuf, "must use absolute path");
		goto done;
	}

	if (decrypt_file (secmem, inname, errbuf, sizeof errbuf,
			  &result_data, &result_len) < 0) {
		snprintf (errbuf, sizeof errbuf, "decrypt error\n");
		goto done;
	}

	snprintf (errbuf, sizeof errbuf, "ok");

done:
	if (*errbuf == 0)
		snprintf (errbuf, sizeof errbuf, "unknown error");
	for (p = errbuf; *p; p++) {
		if (*p == '\n')
			*p = ' ';
	}
	len = strlen (errbuf);
	while (len > 0 && isspace (errbuf[len-1]))
		errbuf[--len] = 0;
	if (verbose)
		printf ("response: %s\n", errbuf);
	write (sock, errbuf, strlen (errbuf));
	write (sock, "\n", 1);

	off = 0;
	togo = result_len;
	while (togo > 0) {
		thistime = write (sock, result_data + off, togo);
		if (thistime <= 0)
			break;
		off += thistime;
		togo -= thistime;
	}

	free (result_data);

	/* caller will close socket */
}

