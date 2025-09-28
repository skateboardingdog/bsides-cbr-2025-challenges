FROM ubuntu:24.04@sha256:9cbed754112939e914291337b5e554b07ad7c392491dba6daf25eef1332a22e8

RUN apt-get update && apt-get install -y build-essential python3 python3-pip

RUN pip3 install pwntools --break-system-packages

WORKDIR /app
COPY ./server .
COPY ./libchat.py .
COPY ./run_bots.py .

EXPOSE 1337

CMD ["/bin/bash", "-c", "./server & python3 run_bots.py"]
