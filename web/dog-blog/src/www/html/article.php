<?php

require_once '../lib/bootstrap.php';

dog_session_start();

if (isset($_GET['lang'])) {
	dog_change_language($_GET['lang']);
}

$article_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;

dog_session_end();

if (file_exists('../tmpl/article.' . $article_id . '.tmpl.php')) {
	require '../tmpl/article.' . $article_id . '.tmpl.php';
}
else {
	header('Location: /');
	die;
}