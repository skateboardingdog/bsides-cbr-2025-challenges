FROM alpine:latest

RUN apk add --no-cache socat

COPY password_game /home/ctf/password_game
COPY entrypoint.sh /home/ctf/entrypoint.sh
RUN chmod 755 /home/ctf/password_game /home/ctf/entrypoint.sh

USER 1000
WORKDIR /home/ctf

ENV FLAG="skbdg{stop_normalizing_unicode}"

ENTRYPOINT ["/home/ctf/entrypoint.sh"]
