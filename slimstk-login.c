#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include "json.h"

void
usage (void)
{
	fprintf (stderr,
		 "usage: slimstk login [confdir]\n"
		 "or, run from a git repository that has done:\n"
		 "     git config slimstk.confdir DIRNAME\n");
	exit (1);
}

char *confdir;

char *
get_and_trim (void)
{
	char buf[1000];

	fflush (stdout);
	if (fgets (buf, sizeof buf, stdin) == NULL) {
		fprintf (stderr, "error reading stdin\n");
		exit (1);
	}

	len = strlen (buf);
	while (len > 0 && isspace (buf[len-1]))
		buf[--len] = 0;

	p = buf;
	while (isspace (*p))
		p++;

	if ((p = strdup (p)) == NULL) {
		fprintf (stderr, "out of memory\n");
		exit (1);
	}

	return (p);
}

int
main (int argc, char **argv)
{
	int c;
	char *cmd;
	FILE *inf;
	char confdir_buf[1000];
	int len;
	char fname[1000];
	int size;
	char *stacks_str;
	int n;
	struct json *stacks;
	char *aws_acct_name;
	char *user;
	char login_profile[1000];

	while ((c = getopt (argc, argv, "")) != EOF) {
		switch (c) {
		default:
			usage ();
		}
	}

	confdir = NULL;

	if (optind < argc) {
		confdir = argv[optind++];
	}

	if (optind != argc)
		usage ();

	if (confdir == NULL && access (".git", X_OK) >= 0) {
		cmd = "git config slimstk.confdir";
		if ((inf = popen (cmd, "r")) == NULL) {
			fprintf (stderr, "can't run %s\n", cmd);
			exit (1);
		}
		if ((fgets (confdir_buf, sizeof confdir_buf, inf)) == NULL)
			confdir_buf[0] = 0;
		fclose (inf);
		len = strlen (confdir_buf);
		while (len > 0 && isspace (confdir_buf[len-1]))
			confdir_buf[--len] = 0;
		confdir = confdir_buf;
	}

	if (confdir == NULL || *confdir == 0)
		usage ();

	sprintf (fname, "%s/stacks.json", confdir);
	if ((inf = fopen (fname, "r")) == NULL) {
		fprintf (stderr, "can't open %s\n", fname);
		exit (1);
	}

	fseek (inf, 0, SEEK_END);
	size = ftell (inf);
	fseek (inf, 0, SEEK_SET);

	if ((stacks_str = malloc (size + 1)) == NULL) {
		fprintf (stderr, "out of memory\n");
		exit (1);
	}

	n = fread (stacks_str, 1, size, inf);
	fclose (inf);
	
	stacks_str[n] = 0;
			
	stacks = json_decode (stacks_str);

	aws_acct_name = json_objref_str (stacks, "aws_acct_name");

	if (*aws_acct_name == 0) {
		printf ("stacks.aws_acct_name not set\n");
		exit (1);
	}

	printf ("aws_acct_name: %s\n", aws_acct_name);

	if ((user = getenv ("USER")) == NULL) {
		printf ("can't find USER in environment\n");
		exit (1);
	}

	sprintf (login_profile, "%s-%s", aws_acct_name, user);
	printf ("login_profile: %s\n", login_profile);

	sprintf (access_key_enc, "%s/access-key-%s.enc",
		 confdir, login_profile);

	if (access (access_key_enc, R_OK) < 0) {
		printf ("need aws access_key and secret_access_key"
			" for %s on %s\n",
			user, aws_acct_name);

		printf ("access_key_id: ");
		access_key_id = get_and_trim ();

		printf ("secret_access_key: ");
		secret_access_key = get_and_trim ();

		if ((outf = fopen ("REMOVE.keys", "w")) == NULL) {
			fprintf (stderr, "can't create REMOVE.keys\n");
			exit (1);
		}
		fprintf (outf, "[%s]\n", login_profile);
	$text .= sprintf ("aws_access_key_id = %s\n", $access_key_id);
	$text .= sprintf ("aws_secret_access_key = %s\n",
			  $secret_access_key);

		


	return (0);
}
