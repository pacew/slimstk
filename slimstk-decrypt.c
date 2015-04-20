#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/un.h>

void
usage (void)
{
	fprintf (stderr, "usage: slimstk-decrypt infile outfile\n");
	exit (1);
}

int
main (int argc, char **argv)
{
	int c;
	char *inname, *outname;
	int inname_len, outname_len;
	int sock;
	struct sockaddr_un server_addr;
	int server_addrlen;
	int xlen;
	char *xpkt;
	char *p;
	struct iovec iov;
	struct msghdr hdr;
	int rc;

	while ((c = getopt (argc, argv, "")) != EOF) {
		switch (c) {
		default:
			usage ();
		}
	}

	if (optind >= argc)
		usage ();

	inname = argv[optind++];

	if (optind >= argc)
		usage ();

	outname = argv[optind++];

	if (optind != argc)
		usage ();

	printf ("my pid %d\n", getpid ());

	sock = socket (AF_UNIX, SOCK_DGRAM, 0);

	memset (&server_addr, 0, sizeof server_addr);
	server_addr.sun_family = AF_UNIX;
	server_addr.sun_path[0] = 0;
	sprintf (server_addr.sun_path + 1, "slimtstk-agent-%d", getuid ());
	server_addrlen = sizeof server_addr;
	
	inname_len = strlen (inname);
	outname_len = strlen (outname);

	xlen = inname_len + 1 + outname_len + 1;
	if ((xpkt = malloc (xlen)) == NULL) {
		fprintf (stderr, "out of memory\n");
		exit (1);
	}
	p = xpkt;
	memcpy (p, inname, inname_len);
	p += inname_len;
	*p++ = 0;
	memcpy (p, outname, outname_len);
	p += outname_len;
	*p++ = 0;

	iov.iov_base = xpkt;
	iov.iov_len = xlen;

	memset (&hdr, 0, sizeof hdr);
	hdr.msg_name = &server_addr;
	hdr.msg_namelen = server_addrlen;
	hdr.msg_iov = &iov;
	hdr.msg_iovlen = 1;
	hdr.msg_flags = 0;
		
	rc = sendmsg (sock, &hdr, 0);
	if (rc < 0) {
		fprintf (stderr, "sendmsg error: %s\n", strerror (errno));
		exit (1);
	}

	return (0);
}
