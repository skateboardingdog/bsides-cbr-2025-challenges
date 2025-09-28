<?php

function T($code) {
	$lang = $_SESSION['lang'] ?? 'en';
	if (!array_key_exists($lang, CONFIG['translations'])) {
		$lang = 'en';
	}
	return CONFIG['translations'][$lang][$code];
}

function dog_valid_language($lang) {
	return preg_replace('/[^a-z]/', '', $lang);
}

function dog_change_language($lang) {
	if ($lang = dog_valid_language($lang)) {
		$_SESSION['lang'] = $lang;
	}
}
