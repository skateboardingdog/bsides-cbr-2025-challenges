#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/random.h>

char* bytes_fromhex(char* in, size_t len) {
    if(len % 2 != 0) return NULL;

    char* out = malloc(len / 2);

    for(int i = 0; i < len; i+=2) {
        char c1 = in[i];
        char c2 = in[i+1];
        if(!isxdigit(c1) || !isxdigit(c2)) {
            return NULL;
        }
        char v = 0;
        v |= (c1 - (isdigit(c1) ? '0' : (islower(c1) ? 'W' : '7'))) << 4;
        v |= (c2 - (isdigit(c2) ? '0' : (islower(c2) ? 'W' : '7')));
        out[i / 2] = v;
    }

    return out;
}

int aes_enc(
    unsigned char* key,
    unsigned char* iv,
    unsigned char* plain,
    int plainlen,
    unsigned char* cipher
) {
    int cipherlen, tmplen;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, cipher, &cipherlen, plain, plainlen);
    EVP_EncryptFinal_ex(ctx, cipher + cipherlen, &tmplen);
    EVP_CIPHER_CTX_free(ctx);
    return cipherlen;
}

int aes_dec(
    unsigned char* key,
    unsigned char* iv,
    unsigned char* cipher,
    int cipherlen,
    unsigned char* plain
) {
    int plainlen, tmplen;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plain, &plainlen, cipher, cipherlen);
    EVP_DecryptFinal_ex(ctx, plain + plainlen, &tmplen);
    EVP_CIPHER_CTX_free(ctx);
    return plainlen;
}

int md5(char* in, int inlen, unsigned char* out) {
    unsigned int outlen;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_md5();
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, in, inlen);
    EVP_DigestFinal_ex(ctx, out, &outlen);
    return outlen;
}

int check_filename(char* filename) {
    unsigned long len = strlen(filename);
    for (int i = 0; i < len; i++) {
        if (filename[i] == '.' || filename[i] == '/') {
            return 0;
        }
    }
    return 1;
}

int read_name(char* name) {
    memset(name, 0, 0x11);
    int r = read(0, name, 0x11);
    if (r && name[r - 1] == '\n') {
        name[r - 1] = '\0';
    }
    return check_filename(name);
}

int directory_exists(char* dirname) {
    struct stat statbuf;

    if (stat(dirname, &statbuf)) {
        perror("Unable to check group directory");
        return 0;
    }

    return S_ISDIR(statbuf.st_mode);
}

int get_user_dirs(char* dirname, char* dirs[3]) {
    DIR *dir;
    struct dirent *entry;
    struct stat file_stat;
    char full_path[PATH_MAX];
    int dir_count = 0;

    dir = opendir(dirname);
    if (!dir) {
        perror("Unable to open directory");
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s/%s", dirname, entry->d_name);
        if (stat(full_path, &file_stat) == -1) {
            perror("Unable to get file status");
            continue;
        }

        if (S_ISDIR(file_stat.st_mode)) {
            strcpy(dirs[dir_count++], entry->d_name);
            if (dir_count >= 3) {
                goto end;
            }
        }
    }

    end:
    closedir(dir);
    return dir_count;
}

int menu() {
    int choice;
    puts("1. Store file");
    puts("2. Retrieve file");
    printf("Choice> ");
    if (scanf("%d", &choice) != 1) {
        puts("Invalid choice");
        exit(-1);
    }
    return choice;
}

unsigned char group[17];
unsigned char user[17];
unsigned char pass[16];
unsigned char server_key[16];

void store_file() {
    unsigned int len;
    unsigned char iv[16];
    char filename[17];
    char p[PATH_MAX];

    printf("Filename> ");
    if (!read_name(filename)) {
        puts("Invalid filename");
        return;
    }

    printf("File size> ");
    scanf("%u", &len);
    if (len > 0x8000) {
        puts("Invalid size");
        return;
    }

    printf("File contents> ");
    unsigned char* ct = malloc(len+16);
    unsigned char* buf = malloc(len);
    read(0, buf, len);

    md5(filename, 16, iv);
    aes_enc(server_key, iv, buf, len, ct);

    snprintf(p, PATH_MAX, "/tmp/%s/%s/%s", group, user, filename);
    FILE* f = fopen(p, "w+");
    fwrite(iv, 16, 1, f);
    fwrite(ct, len, 1, f);
    fflush(f);

    free(buf);
    free(ct);
}

void retrieve_file() {
    char user_dir[PATH_MAX];
    DIR* dir;
    struct dirent *entry;
    struct stat st[5];
    char filenames[5][PATH_MAX];
    int file_count = 0;
    int file_idx;

    snprintf(user_dir, 64, "/tmp/%s/%s", group, user);
    dir = opendir(user_dir);
    if (!dir) {
        perror("Unable to open directory");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(filenames[file_count], sizeof(filenames[file_count]), "%s/%s", user_dir, entry->d_name);
        if (stat(filenames[file_count], &st[file_count]) == -1) {
            perror("Unable to get file status");
            continue;
        }

        if (S_ISREG(st[file_count].st_mode)) {
            printf("%d: %s\n", file_count, filenames[file_count]);
        }

        file_count++;
        if (file_count >= 5) {
            break;
        }
    }

    printf("File index> ");
    scanf("%u", &file_idx);
    if (file_idx >= file_count) {
        puts("Invalid file index!");
        return;
    }

    unsigned int sz = st[file_idx].st_size;
    unsigned char* buf = malloc(sz);
    unsigned char* b = buf;
    unsigned char* pt = malloc(sz);
    int c;
    FILE* f = fopen(filenames[file_idx], "r");
    while ((c = getc(f)) != EOF) {
        *b++ = c;
    }
    aes_dec(server_key, buf, buf+16, sz-16, pt);

    write(1, pt, sz-16);
    puts("");

    free(buf);
    free(pt);
}

int main() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);

    // head -c16 /dev/urandom > server_key.bin
    FILE* f = fopen("server_key.bin", "rb");
    if (!f) {
        perror("Error reading server key file");
        return -1;
    }
    fread(server_key, 1, 0x10, f);

    printf("Input existing group ID or enter to create a new one> ");
    size_t r = read(0, group, 0x11);
    char tmpgroup[PATH_MAX];
    if (r == 1) {
        getrandom(group, 0x10, 0);
        for (int i = 0; i < 0x10; i++) {
            group[i] = 0x41 + (group[i] % 26);
        }
        group[0x10] = '\0';
        printf("Group ID: %s\n", group);
        snprintf(tmpgroup, PATH_MAX, "/tmp/%s", group);
        mkdir((char*)tmpgroup, S_IRWXU);
    } else {
        group[r - 1] = '\0';
        snprintf(tmpgroup, PATH_MAX, "/tmp/%s", group);
        if (!check_filename((char*)group) || !directory_exists(tmpgroup)) {
            return -1;
        }
    }

    for (int i = 0; i < 0x10; i++) {
        server_key[i] ^= group[i];
    }

    char* users[3] = { malloc(17), malloc(17), malloc(17) };
    int user_count = get_user_dirs(tmpgroup, users);

    printf("Username> ");
    if (read_name((char*)user) == 0)  {
        puts("Invalid username");
        return -1;
    }

    int existing_user_idx = -1;
    for (int i = 0; i < user_count; i++) {
        if (strcmp((char*)user, users[i]) == 0) {
            existing_user_idx = i;
        }
    }

    if (existing_user_idx == -1 && user_count >= 3) {
        puts("Only 3 users per group are supported");
        return -1;
    }

    char pass_guess[32];
    aes_enc(server_key, NULL, user, 16, pass);
    if (existing_user_idx >= 0) {
        printf("Password> ");
        r = read(0, pass_guess, 0x20);
        char* p = bytes_fromhex(pass_guess, 0x20);
        if (r == 0x20 && p && memcmp(p, pass, 0x10) == 0) {
            puts("Successfully logged in");
        } else {
            puts("Incorrect password");
            return -1;
        }
    } else {
        char d[PATH_MAX];
        snprintf(d, PATH_MAX, "%s/%s", tmpgroup, user);
        mkdir(d, S_IRWXU);

        printf("Successfully registered. Your password is: ");
        for (int i = 0; i < 0x10; i++) {
            printf("%02x", pass[i]);
        }
        printf("\n");
    }

    while (1) {
        int choice = menu();
        if (choice == 1) {
            store_file();
        } else if (choice == 2) {
            retrieve_file();
        } else {
            puts("Invalid choice");
        }
    }
}
