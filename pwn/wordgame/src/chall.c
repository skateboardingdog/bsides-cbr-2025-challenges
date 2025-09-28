#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define NUM_GUESSWORDS 3

char * GUESSWORDS[NUM_GUESSWORDS] = {
  "OLLIE", 
  "BEAGLE", 
  "KICKFLIP"
};

void init() {

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}

void start_timer(int n) {
  alarm(n);
}

char * init_guessword() {
  FILE* r = fopen("/dev/urandom", "r");
  int seed;
  fread((char*)(&seed), sizeof(int), 1, r);
  fclose(r);
  srand(seed);
  int idx = rand() % NUM_GUESSWORDS;
  char* gw = GUESSWORDS[idx];
  return gw;
}

void print_gameover(char * word, int win) {
  if (win) {
    printf("===== YOU WIN =====\n");
  } else {
    printf("===== GAME OVER =====\n");
  }
  printf("The word was:  %s\n", word);
}

int checkwin(char * gamestate) {
  return !strchr(gamestate, '_');
}

int game() {

  char guesses[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  char * hidden_word = init_guessword();
  int wordlen = strlen(hidden_word);
  char * gamestate = (char*)malloc(wordlen + 1);
  memset(gamestate, '_', wordlen);
  gamestate[wordlen] = 0;
  int remaining_guesses = 100;
  while (remaining_guesses) {
   
    char guess;
    printf("Guess a letter: ");
    scanf("%c", &guess);
    getchar();
    
    if (islower(guess)) {
      printf("Please use uppercase only\n");
      continue;
    }

    char * c = strchr(guesses, guess);

    if (c) {
      *c += ' ';
      for (int i = 0; i < wordlen; i++) {
        if (hidden_word[i] == guess) {

          gamestate[i] = guess;
        }
      }
    } else {
      printf("Invalid guess!\n");
    }

    printf("%s\n", gamestate);

    if (checkwin(gamestate)){
      print_gameover(hidden_word, 1);
      return 0;
    }
    remaining_guesses--;
  }
  print_gameover(hidden_word, 0);
  return 1;
}

int win() {
  system("/bin/sh");
  return 0;
}

int main() {
  init();
  start_timer(60);
  int r = game();
  return r;
}


