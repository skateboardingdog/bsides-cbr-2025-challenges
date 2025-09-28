FROM ubuntu:24.04@sha256:9cbed754112939e914291337b5e554b07ad7c392491dba6daf25eef1332a22e8

WORKDIR /app
COPY ./server .
COPY ./flag.txt .

EXPOSE 1337

CMD ["/bin/bash", "-c", "./server"]
