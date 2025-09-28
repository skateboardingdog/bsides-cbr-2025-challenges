#!/usr/bin/env sh

cp src/Dockerfile Dockerfile.bak
sed -i 's/JWT_SECRET=".*"/JWT_SECRET="redacted_redacted_redacted_redacted_redacted"/' src/Dockerfile
sed -i 's/skbdg{.*}/skbdg{redacted}/' src/Dockerfile
tar -czf ./publish/publish.tar.gz src
mv Dockerfile.bak src/Dockerfile
