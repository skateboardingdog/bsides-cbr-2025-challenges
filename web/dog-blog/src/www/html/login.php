<?php

require_once '../lib/bootstrap.php';

dog_session_start();

if (isset($_GET['lang'])) {
	dog_change_language($_GET['lang']);
}

if (isset($_POST['username']) && isset($_POST['password'])) {
	dog_login($_POST['username'], $_POST['password']);
}

dog_session_end();

if (dog_is_logged_in()) {
	header('Location: /admin');
	die;
}

require '../tmpl/login.tmpl.php';