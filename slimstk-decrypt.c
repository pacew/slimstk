#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <errno.h>
#include <limits.h>

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
	char in_fullname[PATH_MAX + 1], out_fullname[PATH_MAX + 1];
	int in_fullname_len, out_fullname_len;
	int sock;
	struct sockaddr_un server_addr;
	int server_addrlen;
	int xlen;
	char *xpkt;
	char *p;
	int rc;
	char resp[1000];
	int n;
	char cwd[1000];

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

	getcwd (cwd, sizeof cwd);
	if (inname[0] != '/') {
		snprintf (in_fullname, sizeof in_fullname,
			  "%s/%s", cwd, inname);
	} else {
		snprintf (in_fullname, sizeof in_fullname,
			  "%s", inname);
	}

	if (outname[0] != '/') {
		snprintf (out_fullname, sizeof out_fullname,
			  "%s/%s", cwd, outname);
	} else {
		snprintf (out_fullname, sizeof out_fullname,
			  "%s", outname);
	}

	if (access (in_fullname, R_OK) < 0) {
		fprintf (stderr, "can't read: %s\n", in_fullname);
		exit (1);
	}

	printf ("my pid %d\n", getpid ());

	sock = socket (AF_UNIX, SOCK_STREAM, 0);

	memset (&server_addr, 0, sizeof server_addr);
	server_addr.sun_family = AF_UNIX;
	server_addr.sun_path[0] = 0;
	sprintf (server_addr.sun_path + 1, "slimtstk-agent-%d", getuid ());
	server_addrlen = sizeof server_addr;
	
	if (connect (sock, (struct sockaddr *)&server_addr,
		     server_addrlen) < 0) {
		fprintf (stderr, "connect error: %s\n", strerror (errno));
		exit (1);
	}

	in_fullname_len = strlen (in_fullname);
	out_fullname_len = strlen (out_fullname);

	xlen = in_fullname_len + 1 + out_fullname_len + 1;
	if ((xpkt = malloc (xlen)) == NULL) {
		fprintf (stderr, "out of memory\n");
		exit (1);
	}
	p = xpkt;
	memcpy (p, in_fullname, in_fullname_len);
	p += in_fullname_len;
	*p++ = 0;
	memcpy (p, out_fullname, out_fullname_len);
	p += out_fullname_len;
	*p++ = 0;

	if ((rc = write (sock, xpkt, xlen)) != xlen) {
		if (rc < 0) {
			fprintf (stderr, "sendmsg error: %s\n",
				 strerror (errno));
		} else {
			fprintf (stderr, "error sending message\n");
		}
		exit (1);
	}

	if ((n = read (sock, resp, sizeof resp - 1)) < 0) {
		printf ("read error %s\n", strerror (errno));
		exit (1);
	}
	resp[n] = 0;

	printf ("response: %s\n", resp);

	return (0);
}
