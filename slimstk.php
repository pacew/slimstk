<?php

/* tz will be system timezone for unbuntu, UTC for aws */
if (($tz = trim (@file_get_contents ("/etc/timezone"))) == "")
	$tz = "UTC";
date_default_timezone_set ($tz);

$slimstk = NULL;

/* to find safe port: sysctl net.ipv4.ip_local_port_range */
$alternative_ssh_port = 61953; /* random choice */

function slimstk_init () {
	global $slimstk_ext_flag;

	slimstk_init_common ();
	if (@$slimstk_ext_flag)
		slimstk_init_extended ();
}

function slimstk_init_common () {
	global $slimstk, $slimstk_cmd_flag;

	if (isset ($_SERVER['confdir'])) {
		$confdir = $_SERVER['confdir'];
	} else if (file_exists ("/opt/slimstk/stacks.json")) {
		$confdir = "/opt/slimstk";
	} else {
		$fname = sprintf ("%s/.slimstk/current-confdir",
				  $_SERVER['HOME']);
		if (($confdir = trim (file_get_contents ($fname))) == "") {
			printf ("you need to run slimstk-login\n");
			exit (1);
		}
	}

	$stacks_file = sprintf ("%s/stacks.json", $confdir);
	$slimstk = @json_decode (file_get_contents ($stacks_file), true);
	if ($slimstk == NULL) {
		printf ("can't parse %s\n", $stacks_file);
		exit (1);
	}
	$slimstk['confdir'] = $confdir;

	if ($slimstk_cmd_flag) {
		$slimstk['for_webpage'] = 0;
	} else {
		$slimstk['for_webpage'] = 1;
	}

	$vars_file = sprintf ("%s/vars.json", $confdir);
	$slimstk['vars_file'] = $vars_file;
	$slimstk['vars'] = @json_decode (file_get_contents($vars_file), true);

	if (preg_match ('/Amazon.*AMI/',
			@file_get_contents ("/etc/system-release"))) {
		$slimstk['running_on_aws'] = 1;
	} else {
		$slimstk['running_on_aws'] = 0;
	}

	if ($slimstk['for_webpage'] || $slimstk['running_on_aws']) {
		unset ($slimstk['profile']);
	} else {
		$slimstk['profile'] = sprintf ("%s-%s",
					       $slimstk['aws_acct_name'],
					       $_SERVER['USER']);
	}

	if ($slimstk['running_on_aws']
	    && file_exists ("/opt/slimstk/stkname")) {
		global $stkname, $stkinfo;
		$stkname = trim (file_get_contents ("/opt/slimstk/stkname"));
		$stkinfo = $slimstk['stacks'][$stkname];
	}

	if (function_exists ("slimstk_init_extended"))
		slimstk_init_extended ();
}

function slimstk_get_aws_param ($path) {
	$fname = sprintf ("http://169.254.169.254/latest%s", $path);
	return (file_get_contents ($fname));
}

function prettyprint_json ($json) {
	$tname = tempnam ("/tmp", "jq.");
	file_put_contents ($tname, json_encode ($json));
	$cmd = sprintf ("jq . < %s", $tname);
	$ret = shell_exec ($cmd);
	unlink ($tname);
	return ($ret);
}


	

