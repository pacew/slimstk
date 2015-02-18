<?php

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
	} else {
		$slimstk['apache_dir'] = "/etc/httpd";
		$slimstk['apache_conf_avail'] = "";
		$slimstk['apache_conf_enabled']
			= "/home/ec2-user/sites-enabled";
		$slimstk['apachectl'] = "apachectl";
	}
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

function require_https () {
	if (@$_SERVER['HTTPS'] != "on") {
		if (! isset ($_SERVER['ssl_url'])) {
			echo ("invalid SSL configuration");
			exit ();
		}
		$prefix = rtrim ($_SERVER['ssl_url'], '/');
		$suffix = ltrim ($_SERVER['REQUEST_URI'], '/');
		$t = sprintf ("%s/%s", $prefix, $suffix);
		redirect ($t);
	}
}

function make_stylesheet_link () {
	$url = "/style.css";
	$url = sprintf ("%s?s=%s", $url, get_cache_defeater ());
	$ret = sprintf ("<link rel='stylesheet' href='%s' type='text/css' />\n",
			fix_target ($url));

	return ($ret);
}

function make_absolute ($rel) {
	global $ssl_url, $site_url;

	if (preg_match (':^http:', $rel))
		return ($rel);

	if (@$_SERVER['HTTPS'] == "on") {
		$base_url = $ssl_url;
	} else {
		$base_url = $site_url;
	}

	$started_with_slash = 0;
	if (preg_match (':^/:', $rel))
		$started_with_slash = 1;

	/* chop off leading slash */
	$rel = preg_replace (":^/:", "", $rel);

	if ($started_with_slash)
		return ($base_url . $rel);

	$parts = parse_url (@$_SERVER['REQUEST_URI']);
	/* change /test/index.php to /test */
	$dir = preg_replace (':/*[^/]*$:', '', $parts['path']);

	/* change /test to test */
	$dir = preg_replace (":^/:", "", $dir);

	if ($dir == "") {
		$ret = $base_url . $rel;
	} else {
		$ret = $base_url . $dir . "/" . $rel;
	}

	return ($ret);
}

function redirect ($target) {
	$target = make_absolute ($target);

	if (session_id ())
		session_write_close ();
	do_commits ();
	if (ob_list_handlers ())
		ob_clean ();
	header ("Location: $target");
	exit ();
}

$urandom_chars = "0123456789abcdefghijklmnopqrstuvwxyz";
$urandom_chars_len = strlen ($urandom_chars);

function generate_urandom_string ($len) {
	global $urandom_chars, $urandom_chars_len;
	$ret = "";

	$f = fopen ("/dev/urandom", "r");

	for ($i = 0; $i < $len; $i++) {
		$c = ord (fread ($f, 1)) % $urandom_chars_len;
		$ret .= $urandom_chars[$c];
	}
	fclose ($f);
	return ($ret);
}

function get_cache_defeater () {
	global $cache_defeater, $devel_mode;

	if (! isset ($cache_defeater)) {
		if (! $devel_mode
		    && ($f = @fopen ("commit", "r")) != NULL) {
			$val = fgets ($f);
			fclose ($f);
			$val = substr ($val, 7, 8);
		} else {
			$val = generate_urandom_string (8);
		}
		$cache_defeater = $val;
	}

        return ($cache_defeater);
}

function flash ($str) {
	if (session_id ())
		$_SESSION['flash'] .= $str;
}

function redirect_permanent ($target) {
	$target = make_absolute ($target);

	if (session_id ())
		session_write_close ();
	do_commits ();
	if (ob_list_handlers ())
		ob_clean ();
	header ("HTTP/1.1 301 Moved Permanently");
	header ("Location: $target");
	exit ();
}

function fatal ($str = "error") {
	echo ("fatal: " . htmlentities ($str));
	exit();
}

function h($val) {
	return (htmlentities ($val, ENT_QUOTES, 'UTF-8'));
}

/* quoting appropriate for generating xml (like rss feeds) */
function xh($val) {
	return (htmlspecialchars ($val, ENT_QUOTES));
}

function fix_target ($path) {
	$path = preg_replace ('/\&/', "&amp;", $path);
	return ($path);
}

/*
 * use this to conditionally insert an attribute, for example,
 * if $class may contain a class name or an empty string, then do:
 * $body .= sprintf ("<div %s>", mkattr ("class", $class));
 *
 * it is safe to use more than once in the same expression:
 * $body .= sprintf( "<div %s %s>", mkattr("class",$c), mkattr("style",$s));
 */
function mkattr ($name, $val) {
	if (($val = trim ($val)) == "")
		return ("");
	return (sprintf ("%s='%s'",
			 htmlspecialchars ($name, ENT_QUOTES),
			 htmlspecialchars ($val, ENT_QUOTES)));
}

function mail_link ($email) {
	return (sprintf ("<a href='mailto:%s'>%s</a>",
			 fix_target ($email), h($email)));
}

function mklink ($text, $target) {
	if (trim ($text) == "")
		return ("");
	if (trim ($target) == "")
		return (h($text));
	return (sprintf ("<a href='%s'>%s</a>",
			 fix_target ($target), h($text)));
}

function mklink_class ($text, $target, $class) {
	if (trim ($text) == "")
		return ("");

	$attr_href = "";
	$attr_class = "";

	if (trim ($target) != "")
		$attr_href = sprintf ("href='%s'", fix_target ($target));

	if ($class != "")
		$attr_class = sprintf ("class='%s'", $class);

	return (sprintf ("<a %s %s>%s</a>",
			 $attr_href, $attr_class, h($text)));
}

function mklink_attr ($text, $args) {
	$attrs = "";
	foreach ($args as $name => $val) {
		switch ($name) {
		case "href":
			$attrs .= sprintf (" href='%s'", fix_target ($val));
			break;
		default:
			$attrs .= sprintf (" %s='%s'", $name, $val);
			break;
		}
	}

	if (! strstr ($text, "<"))
		$text = h($text);

	return (sprintf ("<a %s>%s</a>", $attrs, $text));

}

function mklink_nw ($text, $target) {
	if (trim ($text) == "")
		return ("");
	if (trim ($target) == "")
		return (h($text));
	return (sprintf ("<a href='%s' target='_blank'>%s</a>",
			 fix_target ($target), h($text)));
}

function mklink_nw_class ($text, $target, $class) {
	if (trim ($text) == "")
		return ("");
	if (trim ($target) == "")
		return (h($text));
	return (sprintf ("<a href='%s' class='%s' target='_blank' >%s</a>",
			 fix_target ($target), ($class), h($text)));
}

function make_confirm ($question, $button, $args) {
	$req = parse_url ($_SERVER['REQUEST_URI']);
	$path = $req['path'];

	$ret = "";
	$ret .= sprintf ("<form action='%s' method='post'>\n", h($path));
	foreach ($args as $name => $val) {
		$ret .= sprintf ("<input type='hidden'"
				 ." name='%s' value='%s' />\n",
				 h($name), h ($val));
	}
	$ret .= h($question);
	$ret .= sprintf (" <input type='submit' value='%s' />\n", h($button));
	$ret .= "</form>\n";
	return ($ret);
}

function mktable ($hdr, $rows) {
	$ncols = count ($hdr);
	foreach ($rows as $row) {
		$c = count ($row);
		if ($c > $ncols)
			$ncols = $c;
	}

	if ($ncols == 0)
		return ("");

	$ret = "";
	$ret .= "<table class='boxed'>\n";
	$ret .= "<thead>\n";
	$ret .= "<tr class='boxed_pre_header'>";
	$ret .= sprintf ("<td colspan='%d'></td>\n", $ncols);
	$ret .= "</tr>\n";

	if ($hdr) {
		$ret .= "<tr class='boxed_header'>\n";

		$colidx = 0;
		if ($ncols == 1)
			$class = "lrth";
		else
			$class = "lth";
		foreach ($hdr as $heading) {
			if (is_array ($heading)) {
				$c = $heading[0];
				$v = $heading[1];
			} else {
				$c = "";
				$v = $heading;
			}

			$ret .= sprintf ("<th class='%s %s'>%s</th>",
					 $class, $c, $v);

			$colidx++;
			$class = "mth";
			if ($colidx + 1 >= $ncols)
				$class = "rth";
		}
		$ret .= "</tr>\n";
	}
	$ret .= "</thead>\n";

	$ret .= "<tfoot>\n";
	$ret .= sprintf ("<tr class='boxed_footer'>"
			 ."<td colspan='%d'></td>"
			 ."</tr>\n",
			 $ncols);
	$ret .= "</tfoot>\n";

	$ret .= "<tbody>\n";

	$rownum = 0;
	foreach ($rows as $row) {
		$this_cols = count ($row);

		if ($this_cols == 0)
			continue;

		if (is_object ($row)) {
			switch ($row->type) {
			case 1:
				$c = "following_row ";
				$c .= $rownum & 1 ? "odd" : "even";
				$ret .= sprintf ("<tr class='%s'>\n", $c);
				$ret .= sprintf ("<td colspan='%d'>",
						 $ncols);
				$ret .= $row->val;
				$ret .= "</td></tr>\n";
				break;
			}
			continue;
		}

		$rownum++;
		$ret .= sprintf ("<tr class='%s'>\n",
				 $rownum & 1 ? "odd" : "even");

		for ($colidx = 0; $colidx < $ncols; $colidx++) {
			if($ncols == 1) {
				$class = "lrtd";
			} else if ($colidx == 0) {
				$class = "ltd";
			} else if ($colidx < $ncols - 1) {
				$class = "mtd";
			} else {
				$class = "rtd";
			}

			$col = @$row[$colidx];

			if (is_array ($col)) {
				$c = $col[0];
				$v = $col[1];
			} else {
				$c = "";
				$v = $col;
			}
			$ret .= sprintf ("<td class='%s %s'>%s</td>\n",
					 $class, $c, $v);
		}

		$ret .= "</tr>\n";
	}

	if (count ($rows) == 0)
		$ret .= "<tr><td>(empty)</td></tr>\n";

	$ret .= "</tbody>\n";
	$ret .= "</table>\n";

	return ($ret);
}

function make_option ($val, $curval, $desc)
{
	global $body;

	if ($val == $curval)
		$selected = "selected='selected'";
	else
		$selected = "";

	$body .= sprintf ("<option value='%s' $selected>", h($val));
	$body .= h ($desc);
	$body .= "</option>\n";
}

function make_option2 ($val, $curval, $desc)
{
	$ret = "";

	if ($val == $curval)
		$selected = "selected='selected'";
	else
		$selected = "";

	$ret .= sprintf ("<option value='%s' $selected>", $val);
	if (trim ($desc))
		$ret .= h ($desc);
	else
		$ret .= "&nbsp;";
	$ret .= "</option>\n";

	return ($ret);
}
