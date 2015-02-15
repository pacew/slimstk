<?php

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
	$schema = array ();
	$schema[] = array ("name" => "sessions",
			   "cols" => array ("session_id" => "text",
					    "updated" => "datetime",
					    "session" => "longtext"));
	$schema[] = array ("name" => "seq",
			   "cols" => array ("lastval" => "integer"));

	dbpatch (NULL, $schema);
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

function getseq () {
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
	