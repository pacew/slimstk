<?php

$slimstk_cmd_flag = 1;

require_once ("/opt/slimstk/slimstk.php");

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

function slimstk_get_aws_credentials () {
	global $slimstk_aws_credentials;

	if (posix_getuid () == 0) {
		/* for root, secret-tool hangs */
		printf ("slimstk_get_aws_credentials: cannot call as root\n");
		exit (1);
	}


	if (! isset ($aws_credentials)) {
		$cmd = sprintf ("secret-tool lookup slimstk %s",
				escapeshellarg ($slimstk['aws_acct_name']));
		if (($creds = trim (shell_exec ($cmd))) == "")
			return (NULL);

		if (! preg_match ("/aws_access_key_id\\s*=\\s*([^\\s*]*)/",
				  $creds, $parts))
			return (NULL);

		$key_id = $parts[1];

		if (! preg_match ("/aws_secret_access_key\\s*=\\s*([^\\s*]*)/",
				  $creds, $parts))
			return (NULL);

		$secret = $parts[1];
		
		$slimstk_aws_credentials = array ("key_id" => $key_id,
						  "secret" => $secret);
	}
	return ($slimstk_aws_credentials);
}
		
function slimstk_aws ($args, $ignore_errors = 0, $json_decode = 1) {
	global $slimstk;

	if (getenv ("AWS_SECRET_ACCESS_KEY") == "") {
		$creds = slimstk_aws

		putenv ("AWS_ACCESS_KEY_ID=" . $key_id);
		putenv ("AWS_SECRET_ACCESS_KEY=" . $secret);


		$cmd = sprintf ("secret-tool lookup slimstk %s",
				escapeshellarg ($slimstk['aws_acct_name']));
		if (($creds = trim (shell_exec ($cmd))) == "") {
			printf ("can't find aws credentials for %s"
				." ... you need to run slimstk login\n",
				$slimstk['aws_acct_name']);
			exit (1);
		}

		if (! preg_match ("/aws_access_key_id\\s*=\\s*([^\\s*]*)/",
				  $creds, $parts)) {
			printf ("can't find aws key_id\n");
			exit (1);
		}
		$key_id = $parts[1];

		if (! preg_match ("/aws_secret_access_key\\s*=\\s*([^\\s*]*)/",
				  $creds, $parts)) {
			printf ("can't find aws secret\n");
			exit (1);
		}
		$secret = $parts[1];

		putenv ("AWS_ACCESS_KEY_ID=" . $key_id);
		putenv ("AWS_SECRET_ACCESS_KEY=" . $secret);
	}

	$cmd = "aws";

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

	if ($json_decode)
		return (json_decode ($output, true));

	return ($output);
}

function slimstk_err ($errno, $errstr, $errfile, $errline, $errcontext) {
	if (! error_reporting ())
		return (FALSE);
	printf ("%s:%d: error (%d): %s\n",
		$errfile, $errline, $errno, $errstr);
	foreach (debug_backtrace () as $frame) {
		printf ("%s:%d\n", @$frame['file'], @$frame['line']);
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

function slimstk_kms_decrypt ($kms_name) {
	if (! preg_match ('/([^.]*)[.]kms$/', $kms_name, $parts))
		return (NULL);

	$region = $parts[1];

	$cmd = sprintf ("aws --region %s kms decrypt"
			." --ciphertext-blob fileb://%s"
			." --query Plaintext"
			." --output text",
			escapeshellarg ($region),
			escapeshellarg ($kms_name));
	$val_base64 = shell_exec ($cmd);
	$cleartext = base64_decode ($val_base64);
	return ($cleartext);
}


function slimstk_get_hosted_zone_id ($name) {
	$name = rtrim ($name, ".");

	$args = array ("route53", "list-hosted-zones");
	$val = slimstk_aws ($args);
	$hosted_zone_id = "";
	foreach ($val['HostedZones'] as $zinfo) {
		$zname = rtrim ($zinfo['Name'], '.');
		if (strcmp ($zname, $name) == 0) {
			$hosted_zone_id = $zinfo['Id'];
			break;
		}
	}
	return ($hosted_zone_id);
}

function slimstk_mktar ($output, $files) {
	$cmd = sprintf ("tar --absolute-names -zcf %s",
			escapeshellarg ($output));
	foreach ($files as $fp) {
		if (strcmp ($fp['src'], $fp['dst']) != 0) {
			$trans = sprintf ('s|^%s$|%s|',
					  $fp['src'], $fp['dst']);
			$cmd .= sprintf (" --transform %s",
					 escapeshellarg ($trans));
		}
	}
	foreach ($files as $fp) {
		$cmd .= sprintf (" %s", escapeshellarg ($fp['src']));
	}
	printf ("%s\n", preg_replace ('/ /', "\n  ", $cmd));
	system ($cmd);
}

function cgetopt ($argc, $argv, $opts) {
	global $optind, $optarg;
	global $opt_nextchar;

	if (! isset ($optind)) {
		$optind = 1;
		$opt_nextchar = 1;
	}

	$optarg = "";
	while ($optind < $argc) {
		if ($argv[$optind][0] != "-")
			break;
		
		if ($argv[$optind] == "--") {
			$optind++;
			break;
		}

		$cur = $argv[$optind];
		$len = strlen ($cur);

		if ($opt_nextchar >= $len) {
			$optind++;
			$opt_nextchar = 1;
			continue;
		}
	
		$c = $cur[$opt_nextchar++];

		if (($optinfo = strstr ($opts, $c)) == NULL) {
			$c = "?";
		} else if (@$optinfo[1] == ":") {
			if ($opt_nextchar < $len) {
				$optarg = substr ($cur, $opt_nextchar);
			} else {
				$optind++;
				$optarg = $argv[$optind];
			}
			$optind++;
			$opt_nextchar = 1;
		}
		
		return ($c);
	}

	return (FALSE);
}
