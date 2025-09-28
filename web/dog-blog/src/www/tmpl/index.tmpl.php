<?php require 'header.tmpl.php'; ?>
    <div class="container">
        <h1><?= T('BLOG_TITLE') ?></h1>
        
        <div class="recent-posts">
            <h2><?= T('BLOG_RECENT_POSTS') ?></h2>
            
            <a href="/article?id=2" class="post-link">
                <div class="post-title">Designing my new blog!</div>
                <div class="post-meta">2 <?= T('BLOG_MINUTE_READ') ?></div>
            </a>
            
            <a href="/article?id=1" class="post-link">
                <div class="post-title">Hello world!</div>
                <div class="post-meta">2 <?= T('BLOG_MINUTE_READ') ?></div>
            </a>
        </div>
    </div>
<?php require 'footer.tmpl.php'; ?>