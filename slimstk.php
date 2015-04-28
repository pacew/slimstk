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
	
	if ($confdir == NULL && file_exists (".git/config")) {
		$confdir = trim (shell_exec ("git config slimstk.confdir"
					     ." 2> /dev/null"));
	}

	for ($idx = 1; $idx < $_SERVER['argc']; $idx++) {
		if (preg_match ('/^--confdir=(.*)/',
				$_SERVER['argv'][$idx], $parts)) {
			$confdir = $parts[1];
			unset ($_SERVER['argv'][$idx]);
			$_SERVER['argv'] = array_merge ($_SERVER['argv']);
			$_SERVER['argc'] = count ($_SERVER['argv']);
			break;
		}
	}

	if ($confdir == NULL) {
		printf ("can't find confdir.\n"
			." if you're in a website repository, run:\n"
			."    slimstk set-confdir DIR\n"
			." if you're doing a global operation,"
			." add --confdir=DIR to the arguments\n");
		exit (1);
	}

	putenv ("confdir=$confdir");

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

function slimstk_dev_decrypt ($enc_name) {
	if (($inf = fopen ($enc_name, "r")) == NULL)
		return (NULL);
	$symkey_cipher = NULL;
	$iv = NULL;
	while (($hdr = trim (fgets ($inf))) != "") {
		$arr = explode (" ", $hdr);
		$user = $arr[0];
		if (strcmp ($user, "-iv") == 0) {
			$iv = base64_decode ($arr[1]);
		} else if (strcmp ($user, $_SERVER['USER']) == 0) {
			$symkey_cipher = base64_decode ($arr[1]);
		}
	}
	
	$cipher = fread ($inf, 10000);
	fclose ($inf);
	
	if ($symkey_cipher == NULL || $iv == NULL)
		return (NULL);

	$privkey_file = sprintf ("%s/.ssh/id_rsa", $_SERVER['HOME']);
	$privkey_resource = openssl_get_privatekey ("file://".$privkey_file);

	/* openssl rsautl -decrypt -inkey id_rsa -in file1 -out file2 */
	openssl_private_decrypt ($symkey_cipher, $symkey_clear,
				 $privkey_resource);

	$clear = openssl_decrypt ($cipher, "aes-256-cbc",
				  $symkey_clear, 0, $iv);

	return ($clear);
}

