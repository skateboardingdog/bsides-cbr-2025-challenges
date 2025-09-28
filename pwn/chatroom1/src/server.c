#include "chatroom.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_PORT 1337
#define MAX_CLIENTS 64

typedef struct Client Client_t;
typedef struct Room Room_t;
typedef struct Server Server_t;

struct Client {
  char *username;
  Room_t *current_room;
  int socket;
};

struct Room {
  Client_t *owner;
  RoomInfo_t *info;
  Room_t *next_room;
  Client_t *client_array[MAX_CLIENTS];
};

// Global singleton context
struct Server {
  int master_socket;
  int client_sockets[MAX_CLIENTS];
  fd_set fds;
  Room_t *room_list;
  Client_t *client_array[MAX_CLIENTS];
};

Server_t *init_server(int port) {

  Server_t *s = (Server_t *)calloc(1, sizeof(Server_t));
  if ((s->master_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    perror("socket failed");
    exit(EXIT_FAILURE);
  }
  int opt = 1;
  if (setsockopt(s->master_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt,
                 sizeof(opt)) < 0) {
    perror("setsockopt failed");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in address;
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(port);

  if (bind(s->master_socket, (struct sockaddr *)&address, sizeof(address)) <
      0) {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }

  if (listen(s->master_socket, 3) < 0) {
    perror("listen failed");
    exit(EXIT_FAILURE);
  }
  return s;
}

int add_client_to_room(Server_t *s, Room_t *room, Client_t *client) {
  int idx = -1;
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (!room->client_array[i]) {
      idx = i;
      break;
    }
  }
  if (idx == -1)
    return idx;
  Room_t *old_room = client->current_room;
  if (old_room) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
      if (old_room->client_array[i] == client) {
        old_room->client_array[i] = NULL;
      }
    }
  }

  room->client_array[idx] = client;
  client->current_room = room;

  return 0;
}

void handle_connect(Server_t *s, int client_idx, CommandMessage_t *msg) {

  Client_t *client = (Client_t *)malloc(sizeof(Client_t));
  s->client_array[client_idx] = client;
  size_t username_len = strnlen(msg->body, MSG_BODY_LEN);
  client->username = (char *)malloc(username_len + 1);
  client->socket = s->client_sockets[client_idx];
  add_client_to_room(s, s->room_list, client);
  strncpy(client->username, msg->body, username_len);
  client->username[username_len] = '\0';
  printf("User: %s connected\n", client->username);
}

void handle_send_message(Server_t *s, int idx, CommandMessage_t *msg) {

  size_t text_len = strlen(msg->body);
  ResponseMessage_t message_to_send = {0};
  message_to_send.kind = MESSAGE;

  snprintf(message_to_send.body, MSG_BODY_LEN, "%s : %s",
           s->client_array[idx]->username, msg->body);

  Room_t *room = s->client_array[idx]->current_room;

  for (int i = 0; i < MAX_CLIENTS; i++) {

    Client_t *c = room->client_array[i];
    if (c) {
      int dest_sd = c->socket;
      if (dest_sd > 0 && dest_sd != s->client_sockets[idx]) {
        send(dest_sd, &message_to_send, sizeof(ResponseMessage_t), 0);
      }
    }
  }
}

void handle_list_rooms(Server_t *s, int idx, CommandMessage_t *msg) {

  Room_t *r;
  ResponseMessage_t *response =
      (ResponseMessage_t *)calloc(1, sizeof(ResponseMessage_t));
  response->kind = ROOM_LIST;
  char *c = response->body;
  int remaining = MSG_BODY_LEN;

  for (r = s->room_list; r != NULL; r = r->next_room) {
    int written = snprintf(c, remaining, "%s", r->info->name);
    if (written >= remaining) {
      break;
    }
    c += written + 1;
    remaining -= written + 1;

    if (remaining <= 0) {
      break;
    }

    if (strlen(r->info->password)) {
      *c = 1;
    }
    c += 3;
    remaining -= 3;
    if (remaining <= 0) {
      break;
    }
  }
  send(s->client_sockets[idx], response, sizeof(ResponseMessage_t), 0);
  free(response);
}

void handle_join_room(Server_t *s, int idx, CommandMessage_t *msg) {

  Room_t *r = NULL;
  ResponseMessage_t response = {0};
  for (r = s->room_list; r; r = r->next_room) {
    if (!strcmp(r->info->name, msg->body))
      break;
  }
  if (r == NULL) {
    response.kind = JOIN_ROOM_FAIL;
    goto send;
  }

  int room_slot = -1;
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (r->client_array[i] == 0) {
      room_slot = i;
      break;
    }
  }
  if (room_slot == -1) {
    response.kind = JOIN_ROOM_FAIL;
    goto send;
  }

  if (strlen(r->info->password)) {
    if (strcmp(r->info->password, msg->body + strlen(msg->body) + 1)) {
      response.kind = JOIN_ROOM_FAIL;
      goto send;
    }
  }

  response.kind = JOIN_ROOM_SUCCESS;
  add_client_to_room(s, r, s->client_array[idx]);
  goto send;

send:
  send(s->client_sockets[idx], &response, sizeof(ResponseMessage_t), 0);
}

void handle_leave_room(Server_t *s, int idx, CommandMessage_t *msg) {
  ResponseMessage_t response = {0};

  Client_t *c = s->client_array[idx];
  if (c->current_room == s->room_list) {
    response.kind = LEAVE_ROOM_FAIL;
  } else {
    response.kind = LEAVE_ROOM_SUCCESS;
    for (int i = 0; i < MAX_CLIENTS; i++) {
      if (c->current_room->client_array[i] == c) {
        c->current_room->client_array[i] = NULL;
        break;
      }
    }
    c->current_room = s->room_list;
  }
  send(s->client_sockets[idx], &response, sizeof(ResponseMessage_t), 0);
}

void handle_create_room(Server_t *s, int idx, CommandMessage_t *msg) {

  char *name = msg->body;
  char *password = msg->body + strlen(name) + 1;

  ResponseMessage_t response = {0};
  Room_t **r;
  if (strlen(name) == 0) {
    response.kind = CREATE_ROOM_FAIL;
    goto send;
  } else {

    for (r = &s->room_list; *r; r = &(*r)->next_room) {
      if (!strcmp(name, (*r)->info->name)) {
        response.kind = CREATE_ROOM_FAIL;
        goto send;
      }
    }

    Room_t *new_room = (Room_t *)malloc(sizeof(Room_t));
    *r = new_room;
    new_room->info = (RoomInfo_t *)malloc(sizeof(RoomInfo_t));
    strncpy(new_room->info->name, name, ROOMNAME_MAXLEN);
    new_room->info->name[ROOMNAME_MAXLEN - 1] = 0;
    if (strlen(password)) {
      strncpy(new_room->info->password, password, ROOMNAME_MAXLEN);
      new_room->info->password[ROOMNAME_MAXLEN - 1] = 0;
    }
    for (int i = 0; i < MAX_CLIENTS; i++) {
      new_room->client_array[i] = NULL;
    }
    new_room->owner = s->client_array[idx];
    response.kind = CREATE_ROOM_SUCCESS;
  }

send:
  send(s->client_sockets[idx], &response, sizeof(ResponseMessage_t), 0);
}

void handle_delete_room(Server_t *s, int idx, CommandMessage_t *msg) {

  ResponseMessage_t response = {0};
  Room_t **r;

  for (r = &s->room_list; *r; r = &(*r)->next_room) {
    if (!strcmp(msg->body, (*r)->info->name))
      break;
  }

  if (!(*r) || !((*r)->owner == s->client_array[idx]) ||
      s->client_array[idx]->current_room == (*r)) {
    response.kind = DELETE_ROOM_FAIL;
  } else {

    for (int i = 0; i < MAX_CLIENTS; i++) {
      if ((*r)->client_array[i]) {
        response.kind = DELETE_ROOM_FAIL;
        goto send;
      }
    }

    response.kind = DELETE_ROOM_SUCCESS;

    Room_t *old = *r;

    *r = (*r)->next_room;
    free(old->info);
    free(old);
  }
send:
  send(s->client_sockets[idx], &response, sizeof(ResponseMessage_t), 0);
}

void handle_disconnect(Server_t *s, int idx) {

  Client_t *client = s->client_array[idx];

  if (!client) {
    return;
  }

  Room_t *room = client->current_room;

  if (room) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
      if (room->client_array[i] == client) {
        room->client_array[i] = NULL;
        break;
      }
    }
  }

  s->client_sockets[idx] = 0;
  free(s->client_array[idx]->username);
  free(s->client_array[idx]);
  s->client_array[idx] = 0;
}

void handle_kick(Server_t *s, int idx, CommandMessage_t *msg) {

  char *room_name = msg->body;
  char *user_name = msg->body + strlen(room_name) + 1;

  ResponseMessage_t response = {0};

  Room_t *r;
  for (r = s->room_list; r; r = r->next_room) {
    if (!strcmp(r->info->name, room_name))
      break;
  }

  if (!r || r->owner != s->client_array[idx]) {
    response.kind = KICK_FAIL;
    goto send;
  }

  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (r->client_array[i] &&
        !strcmp(r->client_array[i]->username, user_name)) {
      if (r == s->room_list) {
        handle_disconnect(s, i);
      } else {
        r->client_array[i]->current_room = s->room_list;
      }
      r->client_array[i] = NULL;
      response.kind = KICK_SUCCESS;
      goto send;
    }
  }

  response.kind = KICK_FAIL;

send:
  send(s->client_sockets[idx], &response, sizeof(ResponseMessage_t), 0);
}

void handle_edit_room(Server_t *s, int idx, CommandMessage_t *msg) {

  char *old_name = msg->body;
  char *new_name = msg->body + strlen(old_name) + 1;

  ResponseMessage_t response = {0};

  Room_t *r;
  for (r = s->room_list; r; r = r->next_room) {
    if (!strcmp(r->info->name, old_name))
      break;
  }

  if (!r || r->owner != s->client_array[idx]) {
    response.kind = EDIT_ROOM_FAIL;
    goto send;
  }

  strncpy(r->info->name, new_name, MIN(strlen(new_name) + 1, ROOMNAME_MAXLEN));
  response.kind = EDIT_ROOM_SUCCESS;

send:
  send(s->client_sockets[idx], &response, sizeof(ResponseMessage_t), 0);
}

void handle_command_message(Server_t *s, int idx, char *msg_buf) {

  CommandMessage_t *msg = (CommandMessage_t *)msg_buf;

  switch (msg->kind) {
  case CONNECT:
    handle_connect(s, idx, msg);
    break;
  case SEND_MESSAGE:
    handle_send_message(s, idx, msg);
    break;
  case LIST_ROOM:
    handle_list_rooms(s, idx, msg);
    break;
  case JOIN_ROOM:
    handle_join_room(s, idx, msg);
    break;
  case LEAVE_ROOM:
    handle_leave_room(s, idx, msg);
    break;
  case CREATE_ROOM:
    handle_create_room(s, idx, msg);
    break;
  case DELETE_ROOM:
    handle_delete_room(s, idx, msg);
    break;
  case KICK:
    handle_kick(s, idx, msg);
    break;
  case EDIT_ROOM:
    handle_edit_room(s, idx, msg);
    break;
  default:
    break;
  }
}

void handle_message(Server_t *s) {
  int new_socket;
  struct sockaddr_in address;
  int addrlen = sizeof(address);
  int max_sd;
  int sd;
  int activity;
  int valread;

  char buffer[sizeof(CommandMessage_t)];

  FD_ZERO(&s->fds);

  FD_SET(s->master_socket, &s->fds);
  max_sd = s->master_socket;

  for (int i = 0; i < MAX_CLIENTS; i++) {
    sd = s->client_sockets[i];

    if (sd > 0) {
      FD_SET(sd, &s->fds);
    }

    if (sd > max_sd) {
      max_sd = sd;
    }
  }

  activity = select(max_sd + 1, &s->fds, NULL, NULL, NULL);

  if ((activity < 0) && (errno != EINTR)) {
    printf("select error");
  }

  if (FD_ISSET(s->master_socket, &s->fds)) {
    if ((new_socket = accept(s->master_socket, (struct sockaddr *)&address,
                             (socklen_t *)&addrlen)) < 0) {
      perror("accept");
      exit(EXIT_FAILURE);
    }

    printf("New connection, socket fd is %d, ip is : %s, port : %d\n",
           new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));

    for (int i = 0; i < MAX_CLIENTS; i++) {
      if (s->client_sockets[i] == 0) {
        s->client_sockets[i] = new_socket;
        printf("Adding to list of sockets as %d\n", i);
        break;
      }
    }
  }
  for (int i = 0; i < MAX_CLIENTS; i++) {
    sd = s->client_sockets[i];

    if (FD_ISSET(sd, &s->fds)) {

      if ((valread = read(sd, buffer, sizeof(CommandMessage_t))) == 0) {
        getpeername(sd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        printf("Host disconnected, ip %s, port %d\n",
               inet_ntoa(address.sin_addr), ntohs(address.sin_port));
        handle_disconnect(s, i);
        close(sd);
      } else {
        handle_command_message(s, i, buffer);
      }
    }
  }
}

int main(int argc, char **argv) {

  uint16_t port;
  if (argc > 1) {
    port = (uint16_t)atoi(argv[1]);
  } else {
    port = DEFAULT_PORT;
  }

  Server_t *s = init_server(port);
  Room_t *landing_room = (Room_t *)calloc(1, sizeof(Room_t));
  landing_room->next_room = 0;
  landing_room->info = (RoomInfo_t *)calloc(1, sizeof(RoomInfo_t));
  strncpy(landing_room->info->name, "Lobby", 6);
  s->room_list = landing_room;

  while (1) {
    handle_message(s);
  }
}
