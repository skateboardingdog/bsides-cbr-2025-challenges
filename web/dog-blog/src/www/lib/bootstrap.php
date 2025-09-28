<?php

define("CONFIG", yaml_parse_file('../config.yaml'));

require_once 'sessions.php';
require_once 'translate.php';
require_once 'auth.php';

if (strlen(CONFIG['secret_key']) < 32) {
	die('Website setup problem. See an admin. Woof.');
}