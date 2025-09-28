<?php

function dog_is_logged_in() {
	return isset($_SESSION['username']);
}

function dog_is_admin() {
	return isset($_SESSION['username']) && $_SESSION['username'] === 'admin';
}

function dog_login($user, $pass) {
	if (!array_key_exists($user, CONFIG['users'])) {
		return false;
	}
	if (password_verify($pass, CONFIG['users'][$user])) {
		$_SESSION['username'] = $user;
		return true;
	}
	return false;
}