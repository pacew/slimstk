<?php

/* tz will be system timezone for unbuntu, UTC for aws */
if (($tz = trim (@file_get_contents ("/etc/timezone"))) == "")
	$tz = "UTC";
date_default_timezone_set ($tz);

$slimstk = NULL;

function slimstk_init () {
	global $slimstk;

	if (isset ($_SERVER['confdir'])) {
		/*
		 * this will be set if we're serving a web page
		 *
		 * it will be in some user's directory for a development
		 * site, or /var/slimstk for production
		 */
		$confdir = $_SERVER['confdir'];
	} else if (file_exists ("/var/slimstk/stacks.json")) {
		/* we're running a command on a production machine */
		$confdir = "/var/slimstk";
	} else {
		/* we're running a command on a devel machine */
		$fname = sprintf ("%s/.slimstk/current-confdir",
				  $_SERVER['HOME']);
		$confdir = trim (file_get_contents ($fname));
		if ($confdir == "") {
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

	if (strcmp ($confdir, "/var/slimstk") != 0) {
		$vars_file = sprintf ("%s/vars.json", $confdir);
		$slimstk['vars_file'] = $vars_file;
		$slimstk['vars'] = @json_decode (file_get_contents($vars_file),
						 true);
	}

	$slimstk['confdir'] = $confdir;

	if (file_exists ("/var/log/cfn-init-cmd.log")) {
		$slimstk['running_on_aws'] = 1;
		unset ($slimstk['profile']);
	} else {
		$slimstk['running_on_aws'] = 0;
		$slimstk['profile'] = sprintf ("%s-%s",
					       $slimstk['aws_acct_name'],
					       $_SERVER['USER']);
	}

	if (isset ($slimstk['inst_stkname'])) {
		global $stkname, $stkinfo;
		$stkname = $slimstk['inst_stkname'];
		$stkinfo = $slimstk['stacks'][$stkname];
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

function prettyprint_json ($json) {
	$tname = tempnam ("/tmp", "jq.");
	file_put_contents ($tname, json_encode ($json));
	$cmd = sprintf ("jq . < %s", $tname);
	$ret = shell_exec ($cmd);
	unlink ($tname);
	return ($ret);
}

function make_db_connection ($dbparams) {
	global $slimstk, $default_dbparams;

	if ($dbparams == NULL) {
		if ($slimstk['running_on_aws']) {
			require_once ("/var/slimstk/dbparams.php");
			$dbparams = $default_dbparams;
		} else {
			$dbparams = array ('host' => '',
					   'user' => '',
					   'passwd' => '');
		}
	}

	try {
		$dsn = sprintf ("mysql:host=%s;charset:utf8",
				$dbparams['host']);
		$pdo = new PDO ($dsn,
				$dbparams['user'], $dbparams['passwd'],
				array (PDO::MYSQL_ATTR_INIT_COMMAND
				       => "set names 'utf8'"));
		$pdo->exec ("set character set utf8");
	} catch (Exception $e) {
		printf ("db connect error %s\n", $e->getMessage ());
		return (NULL);
	}

	return ($pdo);
}

function maybe_create_database ($dbname, $dbparams) {
	global $slimstk;
	if (($pdo = make_db_connection ($dbparams)) == NULL)
		return (-1);
	if ($pdo->exec (sprintf ("use `%s`", $dbname)) === false) {
		printf ("creating database %s\n", $dbname);
		$stmt = sprintf ("create database `%s`"
				 ." default character set utf8"
				 ." default collate utf8_general_ci",
				 $dbname);
		if ($pdo->exec ($stmt) === false) {
			printf ("error running: %s\n", $stmt);
			return (-1);
		}
		if ($slimstk['running_on_aws'] == 0) {
			$stmt = sprintf ("grant all privileges on `%s`.*"
					 ." to `www-data`@`localhost`",
					 $dbname);
			if ($pdo->exec ($stmt) === false) {
				printf ("error running: %s\n", $stmt);
				return (-1);
			}
		}
	}	
	return (0);
}

$db_connections = array ();
$default_db = NULL;

function get_db ($dbname = "", $dbparams = NULL) {
	global $db_connections, $default_db;

	if ($dbname == "")
		$dbname = $_SERVER['siteid'];

	if (($db = @$db_connections[$dbname]) != NULL)
		return ($db);

	$db = (object)NULL;
	$db->dbname = $dbname;
	$db->pdo = make_db_connection ($dbparams);
	if ($db->pdo->exec (sprintf ("use `%s`", $dbname)) === false)
		return (NULL);
	$db->in_transaction = 0;
	
	$db_connections[$dbname] = $db;

	if ($dbparams == NULL)
		$default_db = $db;

	return ($db);
}

function quote_for_db ($db, $str) {
	return ($db->pdo->quote ($str));
}

function ckerr_mysql ($q, $stmt = "") {
	global $body;

	$err = $q->q->errorInfo ();
	if ($err[0] == "00000")
		return;

	$msg1 = sprintf ("DBERR %s %s\n%s\n",
			 strftime ("%Y-%m-%d %H:%M:%S\n"),
			 @$err[2], $stmt);
	$msg2 = "";
	foreach (debug_backtrace () as $frame) {
		if (isset ($frame['file']) && isset ($frame['line'])) {
			$msg2 .= sprintf ("%s:%d\n",
					  $frame['file'], $frame['line']);
		}
	}

	$msg = "<pre>";
	$msg .= htmlentities (wordwrap ($msg1, 120));
	$msg .= htmlentities ($msg2);
	$msg .= "</pre>\n";

	echo ($msg);
	exit ();
}

function query_db ($db, $stmt, $arr = NULL) {
	if (is_string ($db)) {
		echo ("wrong type argument query_db");
		exit ();
	}

	if ($db == NULL)
		$db = get_db ();

	preg_match ("/^[ \t\r\n(]*([a-zA-Z]*)/", $stmt, $parts);
	$op = strtolower (@$parts[1]);

	$q = (object)NULL;

	if ($op != "commit") {
		if ($db->in_transaction == 0) {
			$q->q = $db->pdo->query("start transaction");
			ckerr_mysql ($q);
			$db->in_transaction = 1;
		}
	}

	if ($arr === NULL) {
		$q->q = $db->pdo->prepare ($stmt);
		if (! $q->q->execute (NULL))
			ckerr_mysql ($q, $stmt);
	} else {
		if (! is_array ($arr))
			$arr = array ($arr);
		foreach ($arr as $key => $val) {
			if (is_string ($val) && $val == "")
				$arr[$key] = NULL;
		}
		$q->q = $db->pdo->prepare ($stmt);
		if (! $q->q->execute ($arr))
			ckerr_mysql ($q, $stmt);
	}

	if ($op == "commit")
		$db->in_transaction = 0;

	return ($q);
}

function query ($stmt, $arr = NULL) {
	return (query_db (NULL, $stmt, $arr));
}


function fetch ($q) {
	return ($q->q->fetch (PDO::FETCH_OBJ));
}

function do_commits () {
	global $db_connections;
	foreach ($db_connections as $db) {
		if ($db->in_transaction)
			query_db ($db, "commit");
	}
}

function table_exists ($db, $table_name) {
	$q = query_db ($db, "select 0"
		       ." from information_schema.tables"
		       ." where table_schema = ?"
		       ."   and table_name = ?",
		       array ($db->dbname, $table_name));
	if (fetch ($q))
		return (1);
	return (0);
}

function column_exists ($db, $table_name, $column_name) {
	$q = query_db ($db, "select 0"
		       ." from information_schema.columns"
		       ." where table_schema = ?"
		       ."   and table_name = ?"
		       ."   and column_name = ?",
		       array ($db->dbname, $table_name, $column_name));
	if (fetch ($q))
		return (1);
	return (0);
}

function dbpatch ($db, $tables) {
	if ($db == NULL)
		$db = get_db ();
	foreach ($tables as $tbl) {
		$need_create = 0;
		if (! table_exists ($db, $tbl['name']))
			$need_create = 1;

		foreach ($tbl['cols'] as $colname => $coltype) {
			$stmt = NULL;

			if ($need_create) {
				$need_create = 0;
				$stmt = sprintf ("create table %s (%s %s)",
						 $tbl['name'],
						 $colname, $coltype);
			} else if (! column_exists ($db,
						    $tbl['name'], $colname)) {
				$stmt = sprintf ("alter table %s add %s %s",
						 $tbl['name'],
						 $colname, $coltype);
			}
			if ($stmt) {
				printf ("dbpatch: %s\n", $stmt);
				query_db ($db, $stmt);
			}
		}
	}
}

function slimstk_setup_schema () {
	$sessions_schema[] = array ("name" => "sessions",
				    "cols" => array ("session_id" => "text",
						     "updated" => "datetime",
						     "session" => "longtext"));
	dbpatch (NULL, $sessions_schema);
}

function slimstk_session_open () {}
function slimstk_session_close () {}

function slimstk_session_read ($session_id) {
	$q = query ("select session"
		    ." from sessions"
		    ." where session_id = ?",
		    $session_id);
	if (($r = fetch ($q)) == NULL)
		return ("");
	return ($r->session);
}

function slimstk_session_write ($session_id, $session) {
	$q = query ("select 0"
		    ." from sessions"
		    ." where session_id = ?",
		    $session_id);
	$ts = strftime ("%Y-%m-%d %H:%M:%S");
	if (fetch ($q) == NULL) {
		query ("insert into sessions (session_id, updated, session)"
		       ." values (?,?,?)",
		       array ($session_id, $ts, $session));
	} else {
		query ("update sessions set updated = ?, session = ?"
		       ." where session_id = ?",
		       array ($ts, $session, $session_id));
	}
	do_commits ();
}

function slimstk_session_destroy ($session_id) {
	query ("delete from session where session_id = ?", $session_id);
	do_commits ();
}

function slimstk_session_gc ($lifetime) {
	$ts = strftime ("%Y-%m-%d %H:%M:%S", time () - $lifetime);
	query ("delete from sessions where updated < ?", $ts);
	do_commits ();
}

function slimstk_session () {
	session_set_save_handler ("slimstk_session_open",
				  "slimstk_session_close",
				  "slimstk_session_read",
				  "slimstk_session_write",
				  "slimstk_session_destroy",
				  "slimstk_session_gc");
	session_start ();
}

	

