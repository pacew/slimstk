#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>

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
	char in_fullname[PATH_MAX + 1];
	int sock;
	struct sockaddr_un server_addr;
	int server_addrlen;
	int rc;
	int n;
	char cwd[1000];
	FILE *inf;
	char buf[1000];
	FILE *outf;
	int len;

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

	if (access (in_fullname, R_OK) < 0) {
		fprintf (stderr, "can't read: %s\n", in_fullname);
		exit (1);
	}

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

	n = strlen (in_fullname);
	if ((rc = write (sock, in_fullname, n)) != n) {
		if (rc < 0) {
			fprintf (stderr, "sendmsg error: %s\n",
				 strerror (errno));
		} else {
			fprintf (stderr, "error sending message\n");
		}
		exit (1);
	}

	inf = fdopen (sock, "r");

	if (fgets (buf, sizeof buf, inf) == NULL) {
		fprintf (stderr, "no response from agent\n");
		exit (1);
	}
	len = strlen (buf);
	while (len > 0 && isspace (buf[len-1]))
		buf[--len] = 0;

	if (strcmp (buf, "ok") != 0) {
		fprintf (stderr, "error: %s\n", buf);
		exit (1);
	}

	if (strcmp (outname, "-") == 0) {
		outf = stdout;
	} else {
		if ((outf = fopen (outname, "w")) == NULL) {
			fprintf (stderr, "can't create %s\n", outname);
			exit (1);
		}
	}

	while ((c = getc (inf)) != EOF)
		putc (c, outf);

	fclose (inf);
	fclose (outf);

	return (0);
}
