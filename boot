#! /usr/bin/php
<?php /* -*- mode:php -*- */

require_once ("/opt/slimstk/slimstkcmd.php");
slimstk_cmd_init ();

/*
 * run from userdata in the launch configuration
 *
 * running under su --login ec2-user, so user id is ec2-user and current
 * directory is /home/ec2-user; environment includes USER, HOME; PATH
 * include /usr/local/bin and /home/ec2-user/bin
 */

/* put some useful stuff in the log */
printf ("slimstk php boot script\n");
system ("date");
system ("id");
system ("pwd");
system ("echo umask `umask`");
system ("env");

chmod ($_SERVER['HOME'], 0755);

system ("sudo mkdir -p /www/blank");
system ("sudo cp /dev/null /www/blank/index.html");

$dir = sprintf ("%s/sites-enabled", $_SERVER['HOME']);
system ("mkdir -p $dir");

$httpd_conf = "/etc/httpd/conf/httpd.conf";
$extra = "/opt/slimstk/httpd-extra.conf";
if (! preg_match ('/# slimstk config/', file_get_contents ($httpd_conf))) {
	system ("sudo sh -c 'cat $extra >> $httpd_conf'");
}
system ("sudo service httpd start");

function setup_db_access () {
	global $slimstk, $stkname, $stkinfo;

	$database = $stkinfo['database'];

	$db_passwd_base = sprintf ("dbpass.%s.%s",
				   $slimstk['aws_acct_name'], $database);

	$kms_name = sprintf ("/opt/slimstk/%s.%s.kms",
			     $db_passwd_base, $stkinfo['region']);
	if (! file_exists ($kms_name)) {
		printf ("%s is missing\n", $kms_name);
		return;
	}

	$db_passwd = trim (slimstk_kms_decrypt ($kms_name));

	if ($db_passwd == NULL) {
		printf ("can't decrypt %s\n", $kms_name);
		return;
	}

	$db_host = slimstk_getvar_region ("dbhost.db");

	$text = sprintf ("[client]\n"
			 ."user=root\n"
			 ."host=%s\n"
			 ."password=%s\n",
			 $db_host, $db_passwd);
	$fname = sprintf ("%s/.my.cnf", $_SERVER['HOME']);
	file_put_contents ($fname, $text);
	chmod ($fname, 0600);

	$text = sprintf ("<?php\n"
			 ."\$default_dbparams = array (\n"
			 ." 'host' => '%s',\n"
			 ." 'user' => 'root',\n"
			 ." 'passwd' => '%s'\n"
			 .");\n",
			 $db_host, $db_passwd);
	file_put_contents ("/opt/slimstk/dbparams.php", $text);
}


slimstk_set_region ($stkinfo['region']);

setup_db_access ();

$src = sprintf ("s3://aws-codedeploy-%s/latest/install", $stkinfo['region']);
$dst = "/tmp/codedeploy-install";
system ("aws s3 cp $src $dst");
chmod ($dst, 0755);
system ("date");
printf ("installing codedeploy ... this takes 3 minutes\n");
system ("sudo /tmp/codedeploy-install auto");
system ("date");

printf ("running asg-cycle to kill stales inst(s)\n");
$cmd = sprintf ("/opt/slimstk/asg-cycle %s", escapeshellarg ($stkname));
system ($cmd);

printf ("slimstk boot done\n");
