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
function slimstk_make_kms_for_region ($enc_name, $region) {
	global $slimstk;

	$cmd = sprintf ("slimstk decrypt %s - 2> /dev/null", 
			escapeshellarg ($enc_name));
	if (($plaintext = shell_exec ($cmd)) == NULL) {
		printf ("error running: %s\n", $cmd);
		return (-1);
	}

	$suffix = sprintf ("%s.kms", $region);
	$kms_name = preg_replace ('/enc$/', $suffix, $enc_name);

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
		if (strcmp ($argv[$optind][0], "-") != 0)
			break;
		
		if (strcmp ($argv[$optind], "-") == 0)
			break;

		if (strcmp ($argv[$optind], "--") == 0) {
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

