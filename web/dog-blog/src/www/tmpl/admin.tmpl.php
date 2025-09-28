<?php require 'header.tmpl.php'; ?>
    <div class="container">
        <h1><?= T('BLOG_TITLE') ?></h1>
        <div class="welcome-message">
            <?= dog_is_admin() ? CONFIG['flag'] : T('BLOG_ADMIN_WELCOME'); ?> 
        </div>
    </div>
<?php require 'footer.tmpl.php'; ?>