<?php

$slimstk_ext_flag = 1;

require_once ("slimstk.php");

function slimstk_init_extended () {
	global $slimstk, $siteid, $app_name, $conf_key, $appinfo, $siteinfo;

	if ($slimstk['for_webpage']) {
		$siteid = $_SERVER['siteid'];
	} else {
		$dirname = trim (shell_exec ("git rev-parse --show-toplevel"
					     ." 2> /dev/null"));
		if ($dirname == "")
			$dirname = getcwd ();
		$dirname = basename ($dirname);
		$siteid = preg_replace ('/[.].*/', '', $dirname);
	}

	if (! preg_match ('/-/', $siteid))
		$siteid .= sprintf ("-%s", @$_SERVER['USER']);

	if (! preg_match ('/^([^-]*)-(.*)$/', $siteid, $parts)) {
		printf ("can't determine siteid\n");
		exit (1);
	}

	$slimstk['siteid'] = $siteid;
	$slimstk['app_name'] = $parts[1];
	$slimstk['conf_key'] = $parts[2];
	$slimstk['tmpdir'] = sprintf ("/var/%s", $siteid);

	if (! isset ($slimstk['apps'][$slimstk['app_name']])) {
		printf ("confdir %s doesn't define applications %s\n"
			." ... you may need to run slimstk login\n",
			$slimstk['confdir'], $slimstk['app_name']);
		exit (1);
	}
			

	$issue = file_get_contents ("/etc/issue");
	if (preg_match ('/Ubuntu 14/', $issue)) {
		$slimstk['systype'] = "ubuntu";
		$slimstk['sysvers'] = 14;
		$slimstk['apache_conf_suffix'] = ".conf";
	} else if (preg_match ('/Ubuntu 12/', $issue)) {
		$slimstk['systype'] = "ubuntu";
		$slimstk['sysvers'] = 12;
		$slimstk['apache_conf_suffix'] = "";

	} else if (preg_match ('/Amazon/', $issue)) {
		$slimstk['systype'] = "amazon";
		$slimstk['sysvers'] = 0;
		$slimstk['apache_conf_suffix'] = ".conf";
	} else {
		printf ("unknown system type\n");
		exit (1);
	}

	if (strcmp ($slimstk['systype'], "ubuntu") == 0) {
		$slimstk['apache_dir'] = "/etc/apache2";
		$slimstk['apache_conf_avail'] = "/etc/apache2/sites-available";
		$slimstk['apache_conf_enabled'] = "/etc/apache2/sites-enabled";
		$slimstk['apachectl'] = "apache2ctl";
		$slimstk['apache_user'] = "www-data";
	} else {
		$slimstk['apache_dir'] = "/etc/httpd";
		$slimstk['apache_conf_avail'] = "";
		$slimstk['apache_conf_enabled']
			= "/home/ec2-user/sites-enabled";
		$slimstk['apachectl'] = "apachectl";
		$slimstk['apache_user'] = "apache";
	}

	if ($slimstk['for_webpage'])
		slimstk_session ();
}

function make_url ($host, $port, $ssl_flag) {
	if ($ssl_flag) {
		if ($port == 443) {
			return (sprintf ("https://%s/", $host));
		} else {
			return (sprintf ("https://%s:%d/", $host, $port));
		}
	} else {
		if ($port == 80) {
			return (sprintf ("http://%s/", $host));
		} else {
			return (sprintf ("http://%s:%d/", $host, $port));
		}
	}
}

function make_db_connection ($dbparams = NULL) {
	global $slimstk, $default_dbparams;

	if ($dbparams == NULL) {
		if (! isset ($default_dbparams)) {
			if ($slimstk['running_on_aws']) {
				require_once ("/opt/slimstk/dbparams.php");
			} else {
				/* use auth_socket access to localhost */
				$default_dbparams = array (
					'host' => '',
					'user' => '',
					'passwd' => '');
			}
		}
		$dbparams = $default_dbparams;
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

$db_connections = array ();
$default_db = NULL;

function get_db ($dbname = "", $dbparams = NULL) {
	global $slimstk, $db_connections, $default_db;

	if ($dbname == "") {
		if (! isset ($slimstk['siteid'])) {
			printf ("get_db: no siteid"
				." to identify default database\n");
			exit (1);
		}
		$dbname = $slimstk['siteid'];
	}

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

function quote_for_db ($db = NULL, $str = "") {
	global $default_db;
	if ($db == NULL)
		$db = $default_db;
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
		$q->row_count = $q->q->rowCount ();
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

function getsess ($name) {
	$key = sprintf ("svar%d_%s", $_SERVER['site_port'], $name);
	if (isset ($_SESSION[$key]))
		return ($_SESSION[$key]);
	return (NULL);
}

function putsess ($name, $val) {
	$key = sprintf ("svar%d_%s", $_SERVER['site_port'], $name);
	$_SESSION[$key] = $val;
}

function clrsess () {
	$prefix = sprintf ("svar%d_", $_SERVER['site_port']);
	$prefix_len = strlen ($prefix);
	$del_keys = array ();
	foreach ($_SESSION as $key => $val) {
		if (strncmp ($key, $prefix, $prefix_len) == 0)
			$del_keys[] = $key;
	}
	foreach ($del_keys as $key) {
		unset ($_SESSION[$key]);
	}
}

function get_seq () {
	$q = query ("select lastval"
		    ." from seq"
		    ." limit 1");
	if (($r = fetch ($q)) == NULL) {
		$newval = 100;
		query ("insert into seq (lastval) values (?)",
		       $newval);
	} else {
		$newval = 1 + intval ($r->lastval);
		query ("update seq set lastval = ?",
		       $newval);
	}
	return ($newval);
}

