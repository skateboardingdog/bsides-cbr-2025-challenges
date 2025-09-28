<?php require 'header.tmpl.php'; ?>
    <header class="header">
        <a href="/" class="blog-title"><?= T('BLOG_TITLE') ?></a>
    </header>

    <article class="article-container">
        <h1 class="article-title">Designing my new blog!</h1>
        <div class="article-meta">2 <?= T('BLOG_MINUTE_READ') ?> · <?= T('BLOG_BY') ?> Buddy</div>
        
        <div class="article-content">
            <p>
                I've almost finished my blog now! I'm using an old school PHP + Apache setup, with login, language switching, sessions, and other good features!
            </p>
        </div>
    </article>
<?php require 'footer.tmpl.php'; ?>