<?php

$slimstk = NULL;
$running_on_aws = 0;

function slimstk_init () {
	global $slimstk, $running_on_aws;

	if (file_exists ("/var/log/cfn-init-cmd.log")) {
		$running_on_aws = 1;
		
		$fname = "/var/slimstk/stacks-and-vars.json";
		$slimstk = json_decode (file_get_contents ($fname), true);

		unset ($slimstk['conf_dir']);
		unset ($slimstk['profile']);

		global $stkname, $stkinfo;
		$stkname = $slimstk['inst_stkname'];
		$stkinfo = $slimstk['stacks'][$stkname];

	} else {
		$fname = sprintf ("%s/.slimstk/current-confdir",
				  $_SERVER['HOME']);
		$confdir = trim (file_get_contents ($fname));
		if ($confdir == "") {
			printf ("you need to run slimstk-login\n");
			exit (1);
		}
		$stacks_file = sprintf ("%s/stacks.json", $confdir);

		$slimstk = @json_decode (file_get_contents ($stacks_file),
					 true);

		if ($slimstk == NULL) {
			printf ("can't parse %s\n", $stacks_file);
			exit (1);
		}

		$vars_file = sprintf ("%s/vars.json", $confdir);
		if (file_exists ($vars_file)) {
			$vars = @json_decode (file_get_contents ($vars_file),
					      true);
			if ($vars == NULL) {
				printf ("can't parse %s\n", $vars_file);
				exit (1);
			}
		} else {
			$vars = array ();
		}
		$slimstk['vars_file'] = $vars_file;
		$slimstk['vars'] = $vars;

		$slimstk['conf_dir'] = $confdir;
		$slimstk['profile'] = sprintf ("%s-%s",
					       $slimstk['aws_acct_name'],
					       $_SERVER['USER']);
	}
}

function slimstk_cmd_init () {
	slimstk_init ();
	slimstk_bail_out_on_error ();
}

function slimstk_set_region ($region) {
	global $slimstk;
	$slimstk['current_region'] = $region;
}

function slimstk_writevars () {
	global $slimstk;

	@unlink ($slimstk['vars_file']);
	file_put_contents ($slimstk['vars_file'],
			   json_encode ($slimstk['vars']));
}

function slimstk_getvar ($key) {
	global $slimstk;
	return (@$slimstk['vars'][$key]);
}	

function slimstk_putvar ($key, $val) {
	global $slimstk;

	$slimstk['vars'][$key] = $val;
	slimstk_writevars ();
}

function slimstk_getvar_region ($key) {
	global $slimstk;
	$full_key = sprintf ("%s|%s", $slimstk['current_region'], $key);
	return (slimstk_getvar ($full_key));
}

function slimstk_putvar_region ($key, $val) {
	global $slimstk;
	$full_key = sprintf ("%s|%s", $slimstk['current_region'], $key);
	return (slimstk_putvar ($full_key, $val));
}

function slimstk_aws ($args, $ignore_errors = 0) {
	global $slimstk;

	$cmd = "aws";
	if (@$slimstk['profile']) {
		$cmd .= sprintf (" --profile %s",
				 escapeshellarg ($slimstk['profile']));
	}

	if (@$slimstk['current_region']) {
		$cmd .= sprintf (" --region %s",
				 escapeshellarg ($slimstk['current_region']));
	}

	foreach ($args as $arg) {
		$cmd .= " " . escapeshellarg ($arg);
	}
	if ($ignore_errors)
		$cmd .= " 2> /dev/null";
	printf ("running: %s\n", $cmd);
	exec ($cmd, $arr, $rc);
	$output = implode ("\n", $arr);

	if ($rc != 0) {
		if ($ignore_errors) {
			return (NULL);
		} else {
			printf ("error running: %s\n", $cmd);
			printf ("%s\n", $output);
			exit (1);
		}
	}

	return (json_decode ($output, true));
}

function slimstk_get_aws_param ($path) {
	$fname = sprintf ("http://169.254.169.254/latest%s", $path);
	return (file_get_contents ($fname));
}

function slimstk_err ($errno, $errstr, $errfile, $errline, $errcontext) {
	if (! error_reporting ())
		return (FALSE);
	printf ("%s:%d: error (%d): %s\n",
		$errfile, $errline, $errno, $errstr);
	foreach (debug_backtrace () as $frame) {
		printf ("%s:%d\n", $frame['file'], $frame['line']);
	}
	exit (1);
}

function slimstk_bail_out_on_error () {
	set_error_handler ("slimstk_err", E_ALL);
}

function slimstk_get_gpg_id ($for_user) {
	global $slimstk;

	foreach ($slimstk['users'] as $user => $uinfo) {
		if (strcmp ($user, $for_user) == 0) {
			return ($uinfo['gpg_key_id']);
		}
	}
	return (NULL);
}

function slimstk_get_gpg_ids_for_db ($db) {
	global $slimstk;

	$users = array ();
	foreach ($slimstk['stacks'] as $stkname => $stkinfo) {
		if (strcmp ($stkinfo['database'], $db) == 0) {
			foreach ($stkinfo['admins'] as $user) {
				$users[$user] = 1;
			}
		}
	}

	$ids = array ();
	foreach ($users as $user => $dummy) {
		if (($id = slimstk_get_gpg_id ($user)) == NULL) {
			printf ("can't find gpg id for user %s\n", $user);
			exit (1);
		}
		$ids[$id] = 1;
	}

	return (array_keys ($ids));
}

function slimstk_get_gpg_ids_for_app ($for_app_name) {
	global $slimstk;

	$users = array ();
	foreach ($slimstk['stacks'] as $stkname => $stkinfo) {
		foreach ($stkinfo['sites'] as $siteid => $sinfo) {
			$app_name = preg_replace ('/-.*/', '', $siteid);
			if (strcmp ($app_name, $for_app_name) == 0) {
				foreach ($stkinfo['admins'] as $user) {
					$users[$user] = 1;
				}
			}
		}
	}

	$ids = array ();
	foreach ($users as $user => $dummy) {
		if (($id = slimstk_get_gpg_id ($user)) == NULL) {
			printf ("can't find gpg id for user %s\n", $user);
			exit (1);
		}
		$ids[$id] = 1;
	}

	return (array_keys ($ids));
}

function slimstk_gets () {
	$f = fopen ("php://stdin", "r");
	$resp = fgets ($f);
	fclose ($f);
	return ($resp);
}

/*
 * this probably works for binary plaintext, but php shell_exec() doesn't
 * make an explicit promise of being binary safe.  it is certainly safe
 * if the plaintext is utf8 text.
 *
 * the kms output file is binary, and file_put_contents is documented
 * as binary safe
 */
function slimstk_make_kms_for_region ($gpg_name, $region) {
	global $slimstk;

	$cmd = sprintf ("gpg --decrypt --output - %s", $gpg_name);
	if (($plaintext = shell_exec ($cmd)) == NULL) {
		printf ("error running: %s\n", $cmd);
		return (-1);
	}

	$suffix = sprintf ("%s.kms", $region);
	$kms_name = preg_replace ('/gpg$/', $suffix, $gpg_name);

	$kms_key_id = sprintf ("alias/%s", $slimstk['aws_acct_name']);

	slimstk_set_region ($region);
	$args = array ("kms", "encrypt");
	$args[] = "--key-id";
	$args[] = $kms_key_id;
	$args[] = "--plaintext";
	$args[] = $plaintext;
	$val = slimstk_aws ($args);
	$encrypted = base64_decode ($val['CiphertextBlob']);
	file_put_contents ($kms_name, $encrypted);
	return (0);
}
