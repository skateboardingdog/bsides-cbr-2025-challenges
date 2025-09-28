cp src/init.sql init.sql.bak
sed -i '' 's/skbdg{.*}/skbdg{???}/' src/init.sql
zip -r publish/fruit-shop.zip src/ -x '**/.DS_Store'
mv init.sql.bak src/init.sql