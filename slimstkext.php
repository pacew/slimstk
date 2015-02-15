<?php

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

