<?php

/* tz will be system timezone for unbuntu, UTC for aws */
if (($tz = trim (@file_get_contents ("/etc/timezone"))) == "")
	$tz = "UTC";
date_default_timezone_set ($tz);

$slimstk = NULL;

/* to find safe port: sysctl net.ipv4.ip_local_port_range */
$alternative_ssh_port = 61953; /* random choice */

/* we're serving a web page */
function slimstk_webpage_init ($extended = 0) {
	slimstk_init_common (1, $extended);
}

/* we're a command line tool used for configuration */
function slimstk_cmd_init ($extended = 0) {
	require_once ("slimstkcmd.php");
	slimstk_bail_out_on_error ();
	slimstk_init_common (0, $extended);
}

function slimstk_init_common ($for_webpage, $extended) {
	global $slimstk;

	if (isset ($_SERVER['confdir'])) {
		$confdir = $_SERVER['confdir'];
	} else if (file_exists ("/var/slimstk/stacks.json")) {
		$confdir = "/var/slimstk";
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

	if (! isset ($slimstk['vars'])) {
		$vars_file = sprintf ("%s/vars.json", $confdir);
		if (file_exists ($vars_file)) {
			$slimstk['vars_file'] = $vars_file;
			$slimstk['vars'] = @json_decode (
				file_get_contents($vars_file),
				true);
		}
	}

	$slimstk['serving_web_page'] = $for_webpae;

	if (file_exists ("/var/log/cfn-init-cmd.log")) {
		$slimstk['running_on_aws'] = 1;
	} else {
		$slimstk['running_on_aws'] = 0;
	}

	if ($slimstk['serving_web_page'] || $slimstk['running_on_aws']) {
		unset ($slimstk['profile']);
	} else {
		$slimstk['profile'] = sprintf ("%s-%s",
					       $slimstk['aws_acct_name'],
					       $_SERVER['USER']);
	}

	if ($slimstk['running_on_aws'] && isset ($slimstk['inst_stkname'])) {
		/* stack-config sets inst_stkname */
		global $stkname, $stkinfo;
		$stkname = $slimstk['inst_stkname'];
		$stkinfo = $slimstk['stacks'][$stkname];
	}

	if ($extended) {
		require_once ("slimstkext.php");
		slimstk_init_extended ($for_webpage);
	}
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


	

