<?php

function dog_session_start() {
	$_SESSION = [];
	if (!isset($_COOKIE['DOGSESSION'])) {
		 return;
	}
	$payload = $_COOKIE['DOGSESSION'];
	if (strlen($payload) < 32) {
		return;
	}
	$sig = substr($payload, 0, 32);
	$data = substr($payload, 32);
	if (hash_hmac('md5', $data, CONFIG['secret_key']) !== $sig) {
		return;
	}
	$_SESSION = unserialize(htmlspecialchars_decode($data)) ?: [];
}

function dog_session_end() {
	$data = htmlspecialchars(serialize($_SESSION));
	$sig = hash_hmac('md5', $data, CONFIG['secret_key']);
	setcookie('DOGSESSION', $sig . $data);
}