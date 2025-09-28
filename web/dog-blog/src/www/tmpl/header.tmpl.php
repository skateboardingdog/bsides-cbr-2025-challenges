<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= T('BLOG_TITLE') ?></title>
    <style>
        <?php readfile(__DIR__ . '/index.tmpl.css'); ?>
    </style>
</head>
<body>
    <a href="/" class="back-link"><?= T('BLOG_VIEW') ?></a>

<?php if (dog_is_logged_in()) { ?>
    <a href="/logout" class="logout-button"><?= T('BLOG_LOGOUT') ?></a>
<?php } else { ?>
    <a href="/login" class="admin-link" title="Admin Login">
        🔒
    </a>
<?php } ?>

    <div class="language-selector">
        <button class="language-button">
            English
        </button>
        <div class="language-dropdown">
            <a href="?lang=en" class="language-option active">English</a>
            <a href="?lang=es" class="language-option">Español</a>
            <a href="?lang=fr" class="language-option">Français</a>
        </div>
    </div>

    <div class="paw"></div>
    <div class="paw"></div>
    <div class="paw"></div>
    <div class="paw"></div>
    <div class="paw"></div>
    <div class="paw"></div>
    <div class="paw"></div>
    <div class="paw"></div>
    <div class="paw"></div>
    <div class="paw"></div>
    <div class="paw"></div>
    <div class="paw"></div>