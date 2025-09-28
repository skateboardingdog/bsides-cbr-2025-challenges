<?php

require_once '../lib/bootstrap.php';

dog_session_start();

if (isset($_GET['lang'])) {
	dog_change_language($_GET['lang']);
}

dog_session_end();

if (!dog_is_logged_in()) {
	header('Location: /login');
	die;
}

require_once '../tmpl/admin.tmpl.php';