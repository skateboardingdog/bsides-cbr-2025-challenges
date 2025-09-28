#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <ncurses.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "chatroom.h"

#define COMMAND_MAXLEN 256

static WINDOW *logwin = NULL;

static int log_y = 2;
static const int log_start_y = 2;
static int log_end_y;

typedef enum {
  INPUT_IN_PROGRESS,
  INPUT_COMPLETE,
  INPUT_EXIT_REQUESTED
} InputStatus;

typedef struct Context {

  char username[USERNAME_MAXLEN];
  bool connected;
  int s;
  bool use_tls;
  SSL_CTX *ctx;
  SSL *ssl;

} Context_t;

SSL_CTX *create_context() {
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  method = TLS_client_method();
  ctx = SSL_CTX_new(method);
  if (!ctx) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  return ctx;
}

SSL *wrap_socket(int sock, SSL_CTX *ctx, const char *hostname) {
  SSL *ssl;

  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sock);
  SSL_set_tlsext_host_name(ssl, hostname);

  if (SSL_connect(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
    return NULL;
  }

  return ssl;
}

void unwrap_socket(SSL *ssl, SSL_CTX *ctx) {
  SSL_free(ssl);
  SSL_CTX_free(ctx);
}

int tls_read(SSL *ssl, void *buf, int num) { return SSL_read(ssl, buf, num); }

int tls_write(SSL *ssl, const void *buf, int num) {
  return SSL_write(ssl, buf, num);
}

InputStatus handle_keyboard_input(char *buffer, int *pos, int max_len,
                                  int input_y, int input_x_start) {
  int ch;
  while ((ch = getch()) != ERR) {
    if (ch == '\n' || ch == KEY_ENTER) {
      if (*pos > 0) {
        buffer[*pos] = '\0';
        return INPUT_COMPLETE;
      }
    } else if (ch == KEY_BACKSPACE || ch == 127) {
      if (*pos > 0) {
        (*pos)--;
        mvaddch(input_y, input_x_start + *pos, ' ');
        move(input_y, input_x_start + *pos);
      }
    } else if (*pos < max_len - 1) {
      buffer[*pos] = ch;
      (*pos)++;
      addch(ch);
    }
  }
  return INPUT_IN_PROGRESS;
}

void print_message(const char *msg, bool clear) {
  if (clear) {
    werase(logwin);
    wmove(logwin, 0, 0);
  }

  wprintw(logwin, "%s\n", msg);
  wrefresh(logwin);
}

void print_help() {

  print_message("Options:", false);
  print_message("/list          : list rooms on the server", false);
  print_message("/create <NAME> : create a new room", false);
  print_message("/join <ID>     : join a room", false);
  print_message("/leave         : leave the current room", false);
  print_message("/exit          : close the client", false);
  print_message("/help          : show this help", false);
}

void handle_message(Context_t *c, ResponseMessage_t *buf) {
  print_message(buf->body, false);
}

void handle_room_list(Context_t *c, ResponseMessage_t *buf) {

  char *a = buf->body;
  char *b = buf->body;

  while (true) {
    while (*b++ != 0)
      ;
    print_message(a, false);
    b += 3;
    a = b;
    if (*a == 0)
      break;
  }
}

int handle_server_response(Context_t *c, char *msg_buf) {

  ResponseMessage_t *r = (ResponseMessage_t *)msg_buf;

  switch (r->kind) {
  case CONNECT_SUCCESS:
    break;
  case CONNECT_FAIL:
    break;
  case MESSAGE:
    handle_message(c, r);
    break;
  case ROOM_LIST:
    handle_room_list(c, r);
    break;
  case CREATE_ROOM_SUCCESS:
    print_message("Room created!", false);
    break;
  case CREATE_ROOM_FAIL:
    print_message("Failed to create room", false);
    break;
  case JOIN_ROOM_SUCCESS:
    print_message("Joined!", true);
    break;
  case JOIN_ROOM_FAIL:
    print_message("Failed to join!", false);
    break;
  case LEAVE_ROOM_SUCCESS:
    print_message("You exited back to the Lobby", false);
    break;
  case LEAVE_ROOM_FAIL:
    print_message("You cannot leave the Lobby", false);
    break;
  case DELETE_ROOM_SUCCESS:
    print_message("Room deleted", false);
    break;
  case DELETE_ROOM_FAIL:
    print_message("You must be the owner of a room to delete it", false);
    break;
  case KICK_SUCCESS:
    print_message("User kicked", false);
    break;
  case KICK_FAIL:
    print_message("Failed to kick user", false);
    break;
  case EDIT_ROOM_SUCCESS:
    print_message("Room name changed", false);
    break;
  case EDIT_ROOM_FAIL:
    print_message("Failed to change room name", false);
    break;
  default:
    print_message("Unhandled response from server", false);
    return -1;
  }

  return 0;
}

ssize_t client_write(Context_t *c, const void *buf, size_t len) {
  if (c->use_tls) {
    return tls_write(c->ssl, buf, len);
  } else {
    return send(c->s, buf, len, 0);
  }
}

ssize_t client_read(Context_t *c, void *buf, size_t len) {
  if (c->use_tls) {
    return tls_read(c->ssl, buf, len);
  } else {
    return read(c->s, buf, len);
  }
}

int join_server(Context_t *c) {

  CommandMessage_t join_command = {0};
  join_command.kind = CONNECT;
  strncpy(join_command.body, c->username, USERNAME_MAXLEN);
  if (client_write(c, &join_command, sizeof(CommandMessage_t)) == -1) {
    perror("send");
    return -1;
  }

  c->connected = true;

  return 0;
}

int join_room(Context_t *c, char *room_name, char *password) {

  CommandMessage_t command = {0};
  command.kind = JOIN_ROOM;
  strncpy(command.body, room_name, ROOMNAME_MAXLEN);
  if (password) {
    strncpy(command.body + strlen(room_name) + 1, password, ROOMNAME_MAXLEN);
  }
  if (client_write(c, &command, sizeof(CommandMessage_t)) == -1) {
    perror("send");
    return -1;
  }

  return 0;
}

int leave_room(Context_t *c) {
  CommandMessage_t command = {0};
  command.kind = LEAVE_ROOM;
  if (client_write(c, &command, sizeof(CommandMessage_t)) == -1) {
    perror("send");
    return -1;
  }

  return 0;
}

void list_rooms(Context_t *c) {
  CommandMessage_t list_rooms_command = {0};
  list_rooms_command.kind = LIST_ROOM;
  client_write(c, &list_rooms_command, sizeof(CommandMessage_t));
}

void create_room(Context_t *c, char *name, char *password) {
  if (name == NULL) {
    print_message("Usage: /create <NAME> (<PASSWORD>)", false);
    return;
  }
  CommandMessage_t create_room_command = {0};
  create_room_command.kind = CREATE_ROOM;
  strncpy(create_room_command.body, name, ROOMNAME_MAXLEN);
  if (password) {
    strncpy(create_room_command.body + strlen(name) + 1, password,
            ROOMNAME_MAXLEN);
  }
  client_write(c, &create_room_command, sizeof(CommandMessage_t));
}
int delete_room(Context_t *c, char *room_name) {

  if (!room_name) {
    print_message("Usage: /delete <NAME>", false);
    return -1;
  }

  CommandMessage_t command = {0};
  command.kind = DELETE_ROOM;
  strncpy(command.body, room_name, ROOMNAME_MAXLEN);
  if (client_write(c, &command, sizeof(CommandMessage_t)) == -1) {
    perror("send");
    return -1;
  }

  return 0;
}

int edit_room(Context_t *c, char *old_name, char *new_name) {

  if (!old_name || !new_name) {
    print_message("Usage: /editroom <OLD_NAME> <NEW_NAME>", false);
    return -1;
  }

  CommandMessage_t command = {0};
  command.kind = EDIT_ROOM;
  strncpy(command.body, old_name, ROOMNAME_MAXLEN);
  strncpy(command.body + strlen(old_name) + 1, new_name, ROOMNAME_MAXLEN);
  if (client_write(c, &command, sizeof(CommandMessage_t)) == -1) {
    perror("send");
    return -1;
  }

  return 0;
}

int kick_user(Context_t *c, char *room_name, char *user_name) {

  if (!room_name || !user_name) {
    print_message("Usage: /kick <ROOM> <USER>", false);
    return -1;
  }

  CommandMessage_t command = {0};
  command.kind = KICK;
  strncpy(command.body, room_name, ROOMNAME_MAXLEN);
  strncpy(command.body + strlen(room_name) + 1, user_name, USERNAME_MAXLEN);
  if (client_write(c, &command, sizeof(CommandMessage_t)) == -1) {
    perror("send");
    return -1;
  }

  return 0;
}

int send_message(Context_t *c, char *msg) {

  if (!c->connected) {
    print_message("You must be connected to send a message\n", true);
    return -1;
  }

  CommandMessage_t message_command = {0};
  message_command.kind = SEND_MESSAGE;
  memcpy(message_command.body, msg, MSG_BODY_LEN);
  if (client_write(c, &message_command, sizeof(CommandMessage_t)) == -1) {
    perror("send");
    return -1;
  }

  print_message(msg, false);

  return 0;
}

void process_command(Context_t *c, char *command) {
  if (strncmp(command, "/", 1) == 0) {
    char *cmd_dup = strdup(command);
    char *cmd = cmd_dup;
    char *token = strsep(&cmd, " ");

    if (strcmp(token, "/help") == 0)
      print_help();
    else if (strcmp(token, "/list") == 0) {
      list_rooms(c);
    } else if (strcmp(token, "/create") == 0) {
      char *name = strsep(&cmd, " ");
      char *pw = strsep(&cmd, " ");
      create_room(c, name, pw);
    } else if (strcmp(token, "/join") == 0) {
      char *name = strsep(&cmd, " ");
      char *pw = strsep(&cmd, " ");
      join_room(c, name, pw);
    } else if (strcmp(token, "/leave") == 0) {
      leave_room(c);
    } else if (strcmp(token, "/delete") == 0) {
      char *name = strsep(&cmd, " ");
      delete_room(c, name);
    } else if (strcmp(token, "/editroom") == 0) {
      char *old_name = strsep(&cmd, " ");
      char *new_name = strsep(&cmd, " ");
      edit_room(c, old_name, new_name);
    } else if (strcmp(token, "/kick") == 0) {
      char *room_name = strsep(&cmd, " ");
      char *user_name = strsep(&cmd, " ");
      kick_user(c, room_name, user_name);
    } else if (strcmp(token, "/crash") == 0) {
      *(int64_t *)(0) = 1;
    } else if (strcmp(token, "/exit") == 0) {
    } else
      print_message("Unknown command.", false);
    free(cmd_dup);
  } else {
    send_message(c, (char *)command);
  }
}

void help(char *s) {
  fprintf(stderr, "Usage: %s -s <URL> -p <PORT> -u <USERNAME> [--tls]\n", s);
  exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {

  Context_t *c = (Context_t *)malloc(sizeof(Context_t));
  memset(c, 0, sizeof(Context_t));
  char *server_url = NULL;
  int server_port = 0;
  char *username = NULL;
  int opt;
  int sock;
  struct sockaddr_in serv_addr;
  struct hostent *server;

  static struct option long_options[] = {{"tls", no_argument, 0, 't'},
                                         {0, 0, 0, 0}};

  if (argc < 7) {
    help(argv[0]);
  }

  int option_index = 0;
  while ((opt = getopt_long(argc, argv, "s:p:u:", long_options,
                            &option_index)) != -1) {
    switch (opt) {
    case 't':
      c->use_tls = true;
      break;
    case 's':
      server_url = optarg;
      break;
    case 'p':
      char *endptr;
      long p = strtol(optarg, &endptr, 10);
      if (*endptr != '\0' || p < 1 || p > 65535) {
        fprintf(stderr, "Invalid port number\n");
        exit(EXIT_FAILURE);
      }
      server_port = (int)p;
      break;
    case 'u':
      username = optarg;
      break;
    case '?':
      help(argv[0]);

    default:
      abort();
    }
  }

  strncpy(c->username, username, USERNAME_MAXLEN);
  c->connected = false;

  printf("addr: %s:%d username: %s tls: %s\n", server_url, server_port,
         username, c->use_tls ? "enabled" : "disabled");

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("\n Socket creation error \n");
    return -1;
  }
  memset(&serv_addr, '0', sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(server_port);

  server = gethostbyname(server_url);
  if (server == NULL) {
    fprintf(stderr, "ERROR, no such host\n");
    exit(0);
  }

  memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);

  if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    perror("connect");
    return -1;
  }

  c->s = sock;

  if (c->use_tls) {
    c->ctx = create_context();
    c->ssl = wrap_socket(c->s, c->ctx, server_url);
    if (c->ssl == NULL) {
      fprintf(stderr, "Failed to wrap socket with TLS\n");
      exit(EXIT_FAILURE);
    }
  }

  int flags = fcntl(c->s, F_GETFL, 0);
  fcntl(c->s, F_SETFL, flags | O_NONBLOCK);

  join_server(c);

  initscr();
  scrollok(stdscr, TRUE);
  noecho();
  cbreak();
  curs_set(0);
  nodelay(stdscr, TRUE);
  keypad(stdscr, TRUE);

  char command_buffer[COMMAND_MAXLEN] = {0};
  int command_pos = 0;
  char incoming_command[sizeof(ResponseMessage_t)];

  int max_x, max_y;
  getmaxyx(stdscr, max_y, max_x);
  log_end_y = max_y - 3;
  int log_h = log_end_y - log_start_y + 1;
  int log_w = max_x - 2;
  int log_y0 = log_start_y;
  int log_x0 = 1;

  logwin = newwin(log_h, log_w, log_y0, log_x0);
  scrollok(logwin, TRUE);
  idlok(logwin, TRUE);
  mvhline(max_y - 2, ACS_VLINE, ACS_HLINE, max_x);
  mvprintw(max_y - 2, 2, "Chat");
  print_message("Connected. Use /help for commands.", true);

  const char *prompt = "> ";
  int input_y = max_y - 1;
  int input_x_start = 1 + strlen(prompt);

  fd_set read_fds;
  int max_sd;

  while (1) {
    mvprintw(input_y, 1, "> ");
    move(input_y, input_x_start + command_pos);
    curs_set(1);
    FD_ZERO(&read_fds);
    FD_SET(STDIN_FILENO, &read_fds);
    FD_SET(sock, &read_fds);
    max_sd = (STDIN_FILENO > sock) ? STDIN_FILENO : sock;

    int activity = select(max_sd + 1, &read_fds, NULL, NULL, NULL);

    if ((activity < 0) && (errno != EINTR)) {
      printf("select error\n");
    }

    if (FD_ISSET(sock, &read_fds)) {
      int valread = client_read(c, incoming_command, sizeof(ResponseMessage_t));
      if (valread > 0) {
        handle_server_response(c, incoming_command);
      } else if (valread == 0) {
        print_message("Connection closed by server.", false);
        break;
      } else {
        if (c->use_tls) {
          int ssl_error = SSL_get_error(c->ssl, valread);
          if (ssl_error == SSL_ERROR_WANT_READ ||
              ssl_error == SSL_ERROR_WANT_WRITE) {

          } else {
            print_message("A fatal SSL error occurred.", false);
            ERR_print_errors_fp(stderr);
            break;
          }
        } else {
          if (errno == EWOULDBLOCK || errno == EAGAIN) {
          } else {
            perror("read");
            break;
          }
        }
      }
    }

    if (FD_ISSET(STDIN_FILENO, &read_fds)) {
      InputStatus status = handle_keyboard_input(
          command_buffer, &command_pos, COMMAND_MAXLEN, input_y, input_x_start);

      if (status == INPUT_COMPLETE) {
        if (strcmp(command_buffer, "/exit") == 0) {
          break;
        } else {
          process_command(c, command_buffer);
        }

        memset(command_buffer, 0, COMMAND_MAXLEN);
        command_pos = 0;
        move(input_y, input_x_start);
        clrtoeol();
      }
    }
    refresh();
  }

  endwin();
  if (c->use_tls) {
    unwrap_socket(c->ssl, c->ctx);
  }
  close(c->s);
  free(c);

  return 0;
}
