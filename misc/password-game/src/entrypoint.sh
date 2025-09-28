#!/bin/sh
socat -dd TCP-LISTEN:1337,reuseaddr,fork EXEC:./password_game
