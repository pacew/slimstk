<?php

date_default_timezone_set ("UTC");

$slimstk = NULL;

/* to find safe port: sysctl net.ipv4.ip_local_port_range */
$alternative_ssh_port = 61953; /* random choice */

function slimstk_init () {
	global $slimstk_cmd_flag, $slimstk_ext_flag;

	if (@$slimstk_cmd_flag)
		slimstk_bail_out_on_error ();

	slimstk_init_common ();
	if (@$slimstk_ext_flag)
		slimstk_init_extended ();
}

function slimstk_init_common () {
	global $slimstk, $slimstk_cmd_flag;

	$confdir = @$_SERVER['confdir'];

	if ($confdir == NULL && file_exists ("/opt/slimstk/stacks.json")) {
		$confdir = "/opt/slimstk";
	}
	
	if ($confdir == NULL) {
		$argc = $_SERVER['argc'];
		$argv = $_SERVER['argv'];
		for ($idx = 1; $idx < $argc; $idx++) {
			if (preg_match ('/^--confdir=(.*)/',
					$argv[$idx], $parts)) {
				$confdir = $parts[1];
				unset ($_SERVER['argv'][$idx]);
			}
		}
	}

	if ($confdir == NULL) {
		$confdir = trim (shell_exec ("git config slimstk.confdir"
					     ." 2> /dev/null"));
	}

	if ($confdir == "") {
		printf ("can't find confdir, you need to do one of:\n"
			." add --confdir=DIR\n"
			." run slimstk-login\n"
			." run git config slimstk.confdir DIR\n");
		exit (1);
	}

	$stacks_file = sprintf ("%s/stacks.json", $confdir);
	$slimstk = @json_decode (file_get_contents ($stacks_file), true);
	if ($slimstk == NULL) {
		printf ("can't parse %s\n", $stacks_file);
		exit (1);
	}
	$slimstk['confdir'] = $confdir;

	if (preg_match ('/Amazon.*AMI/',
			@file_get_contents ("/etc/system-release"))) {
		$slimstk['running_on_aws'] = 1;
	} else {
		$slimstk['running_on_aws'] = 0;
	}

	if ($slimstk_cmd_flag) {
		$slimstk['for_webpage'] = 0;

		if (! $slimstk['running_on_aws'] && isset ($_SERVER['USER'])) {
			$profile = sprintf ("%s-%s",
					    $slimstk['aws_acct_name'],
					    $_SERVER['USER']);
			putenv ("AWS_DEFAULT_PROFILE=".$profile);
			$slimstk['profile'] = $profile;
		}
	} else {
		$slimstk['for_webpage'] = 1;
	}

	$vars_file = sprintf ("%s/vars.json", $confdir);
	$slimstk['vars_file'] = $vars_file;
	$slimstk['vars'] = @json_decode (file_get_contents($vars_file), true);

	if ($slimstk['running_on_aws']
	    && file_exists ("/opt/slimstk/stkname")) {
		global $stkname, $stkinfo;
		$stkname = trim (file_get_contents ("/opt/slimstk/stkname"));
		$stkinfo = $slimstk['stacks'][$stkname];
	}
}

function slimstk_get_aws_param ($path) {
	$fname = sprintf ("http://169.254.169.254/latest%s", $path);
	return (file_get_contents ($fname));
}

function prettyprint_json ($json) {
	$tname = tempnam ("/tmp", "jq.");
	$json_encoded = json_encode ($json);
	file_put_contents ($tname, $json_encoded);
	$cmd = sprintf ("jq . < %s 2> /dev/null", $tname);
	$ret = shell_exec ($cmd);
	unlink ($tname);
	if (trim ($ret) == "")
		$ret = $json_encoded;
	return ($ret);
}

function slimstk_aws ($args, $ignore_errors = 0, $json_decode = 1) {
	global $slimstk;

	$cmd = "PATH=\$PATH:/usr/local/bin aws";

	if (@$slimstk['current_region']) {
		$cmd .= sprintf (" --region %s",
				 escapeshellarg ($slimstk['current_region']));
	}

	foreach ($args as $arg) {
		$cmd .= " " . escapeshellarg ($arg);
	}
	if ($ignore_errors) {
		$cmd .= " 2> /dev/null";
	} else {
		$cmd .= " 2>&1";
	}
	if (! $slimstk['for_webpage']) {
		printf ("running: %s\n", $cmd);
	}
	exec ($cmd, $arr, $rc);
	$output = implode ("\n", $arr);

	if ($rc != 0) {
		if ($ignore_errors) {
			return (NULL);
		} else {
			printf ("error %d running: %s\n", $rc, $cmd);
			printf ("%s\n", $output);
			exit (1);
		}
	}

	if ($json_decode)
		return (json_decode ($output, true));

	return ($output);
}

function slimstk_bucket_exists ($bucket) {
	$args = array ("s3api", "list-buckets");
	$val = slimstk_aws ($args);
	foreach ($val['Buckets'] as $binfo) {
		if (strcmp ($binfo['Name'], $bucket) == 0)
			return (1);
	}
	return (0);
}
