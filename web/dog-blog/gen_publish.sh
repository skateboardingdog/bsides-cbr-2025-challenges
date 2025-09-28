cp src/www/config.yaml config.yaml.bak
sed -i '' 's/^  admin: .*/  admin: XXX/;s/^flag: .*/flag: XXX/;s/^secret_key: .*/secret_key: XXX/;' src/www/config.yaml
zip -r publish/dog-blog.zip src/ -x '**/.DS_Store'
mv config.yaml.bak src/www/config.yaml