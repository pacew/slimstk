<?php

function slimstk_find_ports (&$config) {
	global $slimstk;

	$fname = sprintf ("%s/%s%s",
			  $slimstk['apache_conf_avail'],
			  $slimstk['siteid'],
			  $slimstk['apache_conf_suffix']);

	$my_prev_ports = array ();
	if (($f = @fopen ($fname, "r")) != NULL) {
		while (($row = fgets ($f)) != NULL) {
			if (sscanf ($row, "Listen %d", $port) == 1) {
				$my_prev_ports[] = $port;
			}
		}
	}

	if (count ($my_prev_ports) >= 1)
		$config['site_port'] = intval ($my_prev_ports[0]);

	if (count ($my_prev_ports) >= 2)
		$config['ssl_port'] = intval ($my_prev_ports[1]);
}

/* find a free port on ubuntu */
function slimstk_alloc_port () {
	global $ports_used, $port_end, $port_base;
	
	if (! isset ($ports_used)) {
		exec ("grep --no-filename '^[ 	]*Listen'"
		      ." /etc/apache2/conf.d/*"
		      ." /etc/apache2/sites-enabled/*"
		      ." 2> /dev/null",
		      $outlines);
		$ports_used = array ();
		foreach ($outlines as $row) {
			if (sscanf ($row, "Listen %d", $port) == 1) {
				$ports_used[$port] = 1;
			}
		}
	}

	for ($port = $port_end - 1; $port >= $port_base; $port--) {
		if (! isset ($ports_used[$port])) {
			$ports_used[$port] = 1;
			return ($port);
		}
	}
	return (-1);
}

function make_ssl_params ($base) {
	$crtname = sprintf ("%s.crt", $base);
	$keyname = sprintf ("%s.key", $base);
	$chainname = sprintf ("%s.chain.pem", $base);

	if (! file_exists ($crtname))
		return (NULL);

	if (! file_exists ($keyname))
		return (NULL);

	if (! file_exists ($chainname))
		return (NULL);

	$ret = sprintf ("  SSLCertificateKeyFile %s\n"
			."  SSLCertificateFile %s\n"
			."  SSLCertificateChainFile %s\n",
			$keyname, $crtname, $chainname);
	return ($ret);
}

function find_ssl_files ($name) {
	global $slimstk;

	$dirs = array ();
	$dirs[] = getcwd ();
	$dirs[] = $slimstk['confdir'];
	$dirs[] = "/home/ec2-user/slimstk-inst";
	$dirs[] = $slimstk['apache_dir'];

	foreach ($dirs as $dir) {
		$base = sprintf ("%s/%s", $dir, $name);
		if (($ret = make_ssl_params ($base)) != NULL)
			return ($ret);
	}

	$wild = preg_replace ("/^[^.]*[.]/", "wildcard.", $name);

	foreach ($dirs as $dir) {
		$base = sprintf ("%s/%s", $dir, $wild);
		if (($ret = make_ssl_params ($base)) != NULL)
			return ($ret);
	}

	return (NULL);
}

function make_virtual_host ($args) {
	global $slimstk;

	$website_dir = sprintf ("%s/website", getcwd ());
	$dir = $website_dir;
	while ($dir != "") {
		if ((fileperms ($dir) & 0555) != 0555) {
			sprintf ($cmd, "sudo chmod a+rx %s", $dir);
			printf ("%s\n", $cmd);
			system ($cmd);
		}
		$dir = preg_replace (':/[^/*]*$:', '', $dir);
	}

	$ret = "";

	if ($args->port != 80 && $args->port != 443) {
		$ret .= sprintf ("Listen %d\n", $args->port);
	}

	if (strncmp ($args->name, "www.", 4) == 0) {
		$with_www = $args->name;
		$without_www = substr ($args->name, 4);
	} else {
		$with_www = "www.".$args->name;
		$without_www = $args->name;
	}

	$ret .= sprintf ("<VirtualHost *:%d>\n", $args->port);

	$ret .= sprintf ("  ServerName %s\n", $with_www);
	$ret .= sprintf ("  ServerAlias %s\n", $without_www);

	$ret .= sprintf ("  DocumentRoot %s\n", $website_dir);
	$ret .= sprintf ("  FileETag none\n");

	if ($slimstk['systype'] == "ubuntu")
		$ret .= sprintf ("  php_flag session.gc_probability 0\n");

	$ret .= sprintf ("  php_flag html_errors On\n");
	$ret .= sprintf ("  php_flag display_errors On\n");

	if ($args->ssl_flag) {
		$ret .= sprintf ("  SSLEngine on\n");
		$ret .= $args->ssl_files;
	}
		
	$ret .= "\n";

	$ret .= "  RewriteEngine on\n";
	$ret .= "\n";

	$desturl = make_url ($args->name, $args->port, $args->ssl_flag);
	$desturl = rtrim ($desturl, '/');

	$ret .= sprintf ("  RewriteCond %%{HTTP_HOST} ^%s [NC]\n",
			 $with_www);
	$ret .= sprintf ("  RewriteRule ^(.*) %s\$1 [R]\n", $desturl);

	$ret .= "\n";

	if (0) {
		$ret .= "  LogLevel debug\n";
	}
	$ret .= "</VirtualHost>\n\n";

	return ($ret);
}

function find_client_ca ($cafile) {
	global $slimstk;

	$dirs = array ();
	$dirs[] = getcwd ();
	$dirs[] = $slimstk['confdir'];
	$dirs[] = "/home/ec2-user/slimstk-inst";
	$dirs[] = $slimstk['apache_dir'];
	$found = 0;
	foreach ($dirs as $dir) {
		$fullname = sprintf ("%s/%s", $dir, $cafile);
		if (file_exists ($fullname)) {
			$found = 1;
			break;
		}
	}

	if (! $found) {
		printf ("can't find %s\n", $cabase);
		exit (1);
	}

	$ret = sprintf ("  SSLCACertificateFile %s\n"
			."  SSLOptions StdEnvVars\n"
			."  SSLVerifyClient require\n"
			."\n",
			$fullname);
	return ($ret);
}

function slimstk_apache_config ($args) {
	global $slimstk, $stkinfo;

	$config = array ();
	$config['confdir'] = $slimstk['confdir'];
	$config['siteid'] = $slimstk['siteid'];
	$config['site_name'] = $slimstk['app_name'];
	$config['conf_key'] = $slimstk['conf_key'];

	if ($slimstk['systype'] == "amazon") {
		$config['devel_mode'] = 0;

		$sinfo = $stkinfo['sites'][$config['siteid']];

		$config['url_name'] = $sinfo['url_name'];
		$enable_ssl = intval (@$sinfo['ssl']);

		$config['site_port'] = 80;
		$config['ssl_port'] = 443;
	} else {
		$config['devel_mode'] = 1;
		global $port_base, $port_end;

		$nat_info_file = sprintf ("%s/NAT_INFO",
					  $slimstk['apache_dir']);
		$nat_info = @file_get_contents ($nat_info_file);
		if (sscanf ($nat_info, "%s %d", $name, $base) == 2) {
			$config['url_name'] = $name;
			$port_base = $base;
		} else {
			$config['url_name'] = "localhost";
			$port_base = 8000;
		}
		$port_end = $port_base + 900;
		
		slimstk_find_ports ($config);
	}

	if (! isset ($config['site_port']))
		$config['site_port'] = slimstk_alloc_port ();

	$ssl_files = find_ssl_files ($config['url_name']);

	if ($ssl_files) { 
		if (! isset ($config['ssl_port']))
			$config['ssl_port'] = slimstk_alloc_port ();
	} else {
		unset ($config['ssl_port']);
	}

	$apache_conf = "";

	$apache_conf .= sprintf ("<Directory %s/website>\n", getcwd ());
	$apache_conf .= "  Options Indexes FollowSymLinks\n";
	$apache_conf .= "  AllowOverride None\n";
	$apache_conf .= "  Allow from all\n";
	if ($slimstk['systype'] == "ubuntu" && $slimstk['sysvers'] >= 14)
		$apache_conf .= "  Require all granted\n";

	foreach ($config as $name => $val) {
		/* for the current run... */
		$_SERVER[$name] = $val;
		/* and for the website */
		$apache_conf .= sprintf ("  SetEnv %s \"%s\"\n",
					 $name, addslashes ($val));
	}

	$apache_conf .= "\n";

	if (isset ($args['require_client_cert'])) {
		$apache_conf .= find_client_ca ($args['require_client_cert']);
	}

	$apache_conf .= "</Directory>\n";
	$apache_conf .= "\n";

	$args = (object)NULL;
	$args->name = $config['url_name'];
	$args->port = $config['site_port'];
	$args->ssl_flag = 0;
	$apache_conf .= make_virtual_host ($args);

	if (isset ($config['ssl_port'])) {
		$args = (object)NULL;
		$args->name = $config['url_name'];
		$args->port = $config['ssl_port'];
		$args->ssl_flag = 1;
		$args->ssl_files = $ssl_files;
		$apache_conf .= make_virtual_host ($args);
	}

	@unlink ("TMP.conf");
	file_put_contents ("TMP.conf", $apache_conf);
	$config['apache_conf_text'] = $apache_conf;

	$config['site_url'] = make_url ($config['url_name'],
					$config['site_port'], 0);

	if (isset ($config['ssl_port'])) {
		$config['ssl_url'] = make_url ($config['url_name'],
					       $config['ssl_port'], 1);
	}

	return ($config);
}

function slimstk_activate_apache_conf ($config) {
	global $slimstk;
	$apache_conf = $config['apache_conf_text'];

	$active_cfile = sprintf ("%s/%s%s",
				 $slimstk['apache_conf_enabled'],
				 $slimstk['siteid'],
				 $slimstk['apache_conf_suffix']);

	$active_conf = @file_get_contents ($active_cfile);
	if (strcmp (trim ($apache_conf), trim ($active_conf)) == 0)
		return;

	printf ("preparing to update apache config...\n");
	$outlines = NULL;
	$cmd = sprintf ("sudo %s configtest 2>&1", $slimstk['apachectl']);
	exec ($cmd, $outlines, $rc);
	if ($rc != 0) {
		printf ("apache configtest: pre-existing error\n");
		printf ("%s\n", implode ("\n", $outlines));
		exit (1);
	}

	$need_restart = 0;
	if ($active_conf == "")
		$need_restart = 1;

	if ($slimstk['apache_conf_avail']) {
		$avail_cfile = sprintf ("%s/%s%s",
					$slimstk['apache_conf_avail'],
					$slimstk['siteid'],
					$slimstk['apache_conf_suffix']);
		$cmd = sprintf ("sudo cp /dev/stdin %s", $avail_cfile);
		$f = popen ($cmd, "w");
		fwrite ($f, $apache_conf);
		pclose ($f);
		$cmd = sprintf ("sudo chmod a+r %s", $avail_cfile);
		system ($cmd);

		if ($active_conf == "") {
			$cmd = sprintf ("sudo a2ensite -q %s",
					$slimstk['siteid']);
			printf ("%s\n", $cmd);
			system ($cmd);
		}
	} else {
		file_put_contents ($active_cfile, $apache_conf);
	}

	$outlines = NULL;
	$cmd = sprintf ("sudo %s configtest 2>&1", $slimstk['apachectl']);
	exec ($cmd, $outlines, $rc);
	if ($rc != 0) {
		printf ("new config file causes error ... disabling %s\n",
			$slimstk['siteid']);
		printf ("%s\n", implode ("\n", $outlines));

		if ($slimstk['apache_conf_avail']) {
			$cmd = sprintf ("sudo a2dissite %s",
					$slimstk['siteid']);
			system ($cmd);
		} else {
			@unlink ($slimstk['apache_conf_enabled']);
		}
		exit (1);
	}
	
	$cmd = sprintf ("sudo %s graceful", $slimstk['apachectl']);
	printf ("%s\n", $cmd);
	system ($cmd);
}

function slimstk_setup_db () {
	global $slimstk;

	if (($dbname = @$slimstk['siteid']) == "") {
		printf ("siteid must be specified to setup default db\n");
		exit (1);
	}

	if (($pdo = make_db_connection ()) == NULL)
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
	$pdo = NULL;

	$schema = array ();
	$schema[] = array ("name" => "sessions",
			   "cols" => array ("session_id" => "text",
					    "updated" => "datetime",
					    "session" => "longtext"));
	$schema[] = array ("name" => "seq",
			   "cols" => array ("lastval" => "integer"));

	dbpatch (NULL, $schema);

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
