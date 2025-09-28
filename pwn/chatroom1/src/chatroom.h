
#define MSG_BODY_LEN 1024
#define USERNAME_MAXLEN 256
#define ROOMNAME_MAXLEN 256

enum CommandKind {
  CONNECT,
  SEND_MESSAGE,
  LIST_ROOM,
  JOIN_ROOM,
  LEAVE_ROOM,
  CREATE_ROOM,
  DELETE_ROOM,
  KICK,
  EDIT_ROOM,
};

typedef struct CommandMessage {

  enum CommandKind kind;
  
  char body[MSG_BODY_LEN];


} CommandMessage_t;

enum ResponseKind {
  CONNECT_SUCCESS,
  CONNECT_FAIL,
  MESSAGE,
  ROOM_LIST,
  JOIN_ROOM_SUCCESS,
  JOIN_ROOM_FAIL,
  LEAVE_ROOM_SUCCESS,
  LEAVE_ROOM_FAIL,
  CREATE_ROOM_SUCCESS,
  CREATE_ROOM_FAIL,
  DELETE_ROOM_SUCCESS,
  DELETE_ROOM_FAIL,
  KICK_SUCCESS,
  KICK_FAIL,
  EDIT_ROOM_SUCCESS,
  EDIT_ROOM_FAIL,
};

typedef struct ResponseMessage {
  enum ResponseKind kind;

  char body[MSG_BODY_LEN];
} ResponseMessage_t;


typedef struct RoomInfo {

  char name[ROOMNAME_MAXLEN];
  char password[ROOMNAME_MAXLEN];

} RoomInfo_t;
