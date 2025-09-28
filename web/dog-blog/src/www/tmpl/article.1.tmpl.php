<?php require 'header.tmpl.php'; ?>
    <header class="header">
        <a href="/" class="blog-title"><?= T('BLOG_TITLE') ?></a>
    </header>

    <article class="article-container">
        <h1 class="article-title">Hello world!</h1>
        <div class="article-meta">2 <?= T('BLOG_MINUTE_READ') ?> · <?= T('BLOG_BY') ?> Buddy</div>
        
        <div class="article-content">
            <p>
                Hello world! Welcome to my new blog. Here I will post all the lastest news about skateboarding and dogs.
            </p>
        </div>
    </article>
<?php require 'footer.tmpl.php'; ?>