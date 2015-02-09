<?php

$slimstk = NULL;

function slimstk_get_logged_in_acct () {
	$fname = sprintf ("%s/.aws/credentials", $_SERVER['HOME']);
	$text = file_get_contents ($fname);
	if ( ! preg_match ('/[[](.*)-(.*)[]]/', $text, $parts))
		return (NULL);

	$aws_acct_name = $parts[1];
	$user = $parts[2];

	if (strcmp ($_SERVER['USER'], $user) != 0)
		return (NULL);

	return ($aws_acct_name);
}

function slimstk_set_acct ($aws_acct_name) {
	global $slimstk;

	$confdir=trim(file_get_contents(sprintf("confdir-%s",$aws_acct_name)));
	if (! file_exists ($confdir)) {
		printf ("%s does not exist\n", $confdir);
		exit (1);
	}

	$stacks_file = sprintf ("%s/stacks.json", $confdir);
	if (! file_exists ($confdir)) {
		printf ("%s does not exist\n", $confdir);
		exit (1);
	}
	$slimstk = @json_decode (file_get_contents ($stacks_file), true);

	if ($slimstk == NULL) {
		printf ("can't parse %s\n", $stacks_file);
		exit (1);
	}

	if (strcmp (@$slimstk['aws_acct_name'], $aws_acct_name) != 0) {
		printf ("unexpected aws_acct_name in %s\n", $stacks_file);
		exit (1);
	}
	
	$vars_file = sprintf ("%s/vars.json", $confdir);
	if (file_exists ($vars_file)) {
		$vars = @json_decode (file_get_contents ($vars_file), true);
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
				       $aws_acct_name, $_SERVER['USER']);
}

function slimstk_cmd_init () {
	slimstk_bail_out_on_error ();

	if (($aws_acct_name = slimstk_get_logged_in_acct ()) == NULL) {
		printf ("do aws-login first\n");
		exit (1);
	}
	slimstk_set_acct ($aws_acct_name);
}

function slimstk_init () {
	global $slimstk;

	$fname = "/var/slimstk/stacks-and-vars.json";
	$slimstk = json_decode (file_get_contents ($fname), true);

	unset ($slimstk['conf_dir']);
	unset ($slimstk['profile']);
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
