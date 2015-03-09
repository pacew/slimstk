#! /usr/bin/php
<?php /* -*- mode:php -*- */

require_once ("/opt/slimstk/slimstkcmd.php");
slimstk_init ();

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

chmod ($_SERVER['HOME'], 0755);
system ("sudo usermod -a -G apache ec2-user");

$bashrc = ". /etc/bashrc\n"
	."umask 2\n";
file_put_contents ($_SERVER['HOME']."/.bashrc", $bashrc);

system ("sudo mkdir -p /www/blank");
system ("sudo cp /dev/null /www/blank/index.html");

$dir = sprintf ("%s/sites-enabled", $_SERVER['HOME']);
system ("mkdir -p $dir");

if (! preg_match ('/umask/', file_get_contents ("/etc/sysconfig/httpd"))) {
	system ("sudo sh -c '(echo; echo umask 2) >> /etc/sysconfig/httpd'");
}

$httpd_conf = "/etc/httpd/conf/httpd.conf";
$extra = "/opt/slimstk/httpd-extra.conf";
if (! preg_match ('/# slimstk config/', file_get_contents ($httpd_conf))) {
	system ("sudo sh -c 'cat $extra >> $httpd_conf'");
}
system ("sudo service httpd start");

function setup_dns () {
	global $slimstk, $stkname, $stkinfo;

	if (($server_domain = @$stkinfo['server_domain']) == "")
		return;

	$hosted_zone_id = slimstk_get_hosted_zone_id ($server_domain);
	if ($hosted_zone_id == "") {
		printf ("setup_dns: server_domain %s not found in route53\n",
			$server_domain);
		return;
	}

	$val = slimstk_get_aws_param ("/meta-data/placement/availability-zone");
	$zone_letter = substr ($val, -1);

	$public_ipv4 = slimstk_get_aws_param ("/meta-data/public-ipv4");

	$abs_name = sprintf ("%s%s.%s.",
			     $stkname, $zone_letter, $server_domain);

	printf ("setup_dns %s => %s\n", $abs_name, $public_ipv4);

	$items = array ();
	$items[] = array ("Action" => "UPSERT", 
			  "ResourceRecordSet" => array (
				  "Name" => $abs_name, 
				  "Type" => "A", 
				  "TTL" => 30, 
				  "ResourceRecords" => array (
					  array ("Value" => $public_ipv4)
					  )
				  )
		);

	$change_batch = array ("Changes" => $items);

	$args = array ("route53", "change-resource-record-sets");
	$args[] = "--hosted-zone-id";
	$args[] = $hosted_zone_id;
	$args[] = "--change-batch";
	$args[] = json_encode ($change_batch);
	$val = slimstk_aws ($args);
	printf ("%s\n", json_encode ($val));
}

function decrypt_files () {
	global $stkinfo;
	$desired_suffix = sprintf (".%s.kms", $stkinfo['region']);
	$suffix_len = strlen ($desired_suffix);

	$dir = opendir ("/opt/slimstk");
	while (($fname = readdir ($dir)) != NULL) {
		$suffix = substr ($fname, - $suffix_len);
		if (strcmp ($suffix, $desired_suffix) != 0)
			continue;
		$kms_name = sprintf ("/opt/slimstk/%s", $fname);
		$clear_name = sprintf ("/opt/slimstk/%s",
				       substr ($fname, 0, - $suffix_len));

		printf ("decrypting %s\n", $kms_name);
		$cleartext = slimstk_kms_decrypt ($kms_name);
		file_put_contents ($clear_name, $cleartext);
	}
}

function setup_db_access () {
	global $slimstk, $stkname, $stkinfo;

	$database = $stkinfo['database'];

	$dbpass_file = sprintf ("/opt/slimstk/dbpass.%s.%s",
				$slimstk['aws_acct_name'], $database);

	$db_passwd = trim (@file_get_contents ($dbpass_file));

	if ($db_passwd == NULL) {
		printf ("can't find db password in %s\n", $dbpass_file);
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

decrypt_files ();
setup_db_access ();
setup_dns ();

$src = sprintf ("s3://aws-codedeploy-%s/latest/install", $stkinfo['region']);
$dst = "/tmp/codedeploy-install";
system ("aws s3 cp $src $dst");
chmod ($dst, 0755);
system ("date");
system ("sudo /tmp/codedeploy-install auto");
system ("date");

if (1) {
	printf ("scheduling asg-cycle to kill stale inst(s)\n");
	$outf = popen ("at 'now+5minutes'", "w");
	$cmd = sprintf ("/opt/slimstk/asg-cycle %s %s",
			escapeshellarg ($slimstk['confdir']),
			escapeshellarg ($stkname));
	fwrite ($outf, $cmd);
	pclose ($outf);
}

printf ("slimstk boot done\n");
