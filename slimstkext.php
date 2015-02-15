<?php

function slimstk_init_extended ($for_webpage) {
	global $slimstk, $siteid, $app_name, $conf_key, $appinfo;

	$siteid = NULL;
	$app_name = NULL;
	$conf_key = NULL;
	$appinfo = NULL;

	if ($for_webpage) {
		$siteid = $_SERVER['siteid'];
	} else {
		$dirname = shell_exec ("git rev-parse --show-toplevel"
				       ." 2> /dev/null");
		if ($dirname) {
			$dirname = basename ($dirname);
			if (preg_match ('/^(.*)-([^-]*)$/', $parts)) {
				$app_name = $parts[1];
				$conf_key = $parts[2];
			} else {
				$app_name = $dirname;
				$conf_key = $_SERVER['USER'];
			}
			$siteid = sprintf ("%s-%s", $app_name, $conf_key);
		}
	}

	if (isset ($app_name))
		$appinfo = @$slimstk['apps'][$app_name];
	if ($appinfo == NULL)
		$appinfo = array ();
}
