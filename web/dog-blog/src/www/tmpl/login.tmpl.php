<?php require 'header.tmpl.php'; ?>
    <div class="login-container">
        <h1><?= T('BLOG_TITLE') ?></h1>
        
        <form action="/login" method="POST">
            <div class="form-group">
                <label for="username"><?= T('BLOG_USERNAME') ?></label>
                <input type="text" id="username" name="username" required autofocus>
            </div>
            
            <div class="form-group">
                <label for="password"><?= T('BLOG_PASSWORD') ?></label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="login-button"><?= T('BLOG_SIGN_IN') ?></button>
        </form>
    </div>
<?php require 'footer.tmpl.php'; ?>