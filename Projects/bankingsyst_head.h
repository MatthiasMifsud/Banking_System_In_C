#ifndef BANKINGSYST_H
#define BANKINGSYST_H

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#define MAX_NAME 256
#define TABLE_SIZE 20
#define MAX_ID 100
#define MAX_PASSWORD_LENGTH 100
#define USER_FILE_NAME "user-admin/bankuser.csv"
#define ADMIN_FILE_NAME "user-admin/bankadmin.csv"
#define MAX_LINE_LENGTH 256
#define MAX_LOGIN_ATTEMPTS 10

#define SALT_SIZE 16
#define HASH_SIZE 32

typedef struct person {
    char name[MAX_NAME];
    char surname[MAX_NAME];
    char id[MAX_ID];
    char password[MAX_PASSWORD_LENGTH];
    unsigned char salt[SALT_SIZE];
    unsigned char password_hash[HASH_SIZE];
    double balance;
} person;

typedef struct administrator{
    char name[MAX_NAME];
    char surname[MAX_NAME];
    char id[MAX_ID];
    char password[MAX_PASSWORD_LENGTH];
    unsigned char salt[SALT_SIZE];
    unsigned char password_hash[HASH_SIZE];
} administrator;

extern person *user_hash_table[TABLE_SIZE];
extern administrator *admin_hash_table[TABLE_SIZE];

unsigned int hash(char *id);
void init_hash_table();
bool user_hash_table_insert(person *user);
person *user_hash_table_lookup(char *id);
person *user_hash_table_delete(char *id);
bool admin_hash_table_insert(administrator *admin);
administrator *admin_hash_table_lookup(char *id);
administrator *admin_hash_table_delete(char *id);
void hash_password(const char *password, unsigned char *salt, unsigned char *password_hash);
bool verify_hashed_password(const char *password, unsigned char *salt, unsigned char *password_hash);
int user_write_file();
int admin_write_file();
int user_read_file();
int admin_read_file();
void user_update_file();
void admin_update_file();
bool login_user(char *id, char *password);
bool login_admin(char *id, char *password);
void check_user_balance(person *current_user);
void user_personal_info(person *current_user, const char *password);
void setting_transactions(person *current_user);
void read_transaction_file(char *id);
void delete_user();
void lookup_users();
void list_users();
void admin_personal_info(administrator *current_admin, const char *password);
void delete_admin();
void lookup_admins();
void list_admins();
void welcome_menu();
void user_menu();
void admin_menu();
void clean_hash();

#endif // BANKING_SYSTEM_H