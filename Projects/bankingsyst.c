//gcc -o bank bankingsyst.c -I$(brew --prefix openssl)/include -L$(brew --prefix openssl)/lib -lssl -lcrypto
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#define MAX_NAME 256
#define TABLE_SIZE 20
#define MAX_ID 100
#define MAX_PASSWORD_LENGTH 20
#define USER_FILE_NAME "bankuser.csv"
#define ADMIN_FILE_NAME "bankadmin.csv"
#define MAX_LINE_LENGTH 256
#define NEW_USER_BALANCE 50.0
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

typedef struct admin{
    char name[MAX_NAME];
    char surname[MAX_NAME];
    char id[MAX_ID];
    char password[MAX_PASSWORD_LENGTH];
    unsigned char salt[SALT_SIZE];
    unsigned char password_hash[HASH_SIZE];
} admin;

//necessary functions for hashing by id
person *user_hash_table[TABLE_SIZE];
person deleted_user_entry = {.id = ""}; // Marker for deleted entries

admin *admin_hash_table[TABLE_SIZE];
admin deleted_admin_entry = {.id = ""}; // Marker for deleted entries

unsigned int hash(char *id) {
    unsigned long hash = 5381;
    int c;
    while ((c = *id++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash % TABLE_SIZE;
}

//initilising both user and admin hash tables
void init_hash_table() {
    for (int i = 0; i < TABLE_SIZE; i++) {
        user_hash_table[i] = NULL;
        admin_hash_table[i] = NULL;
    }
}

//user hash table
bool user_hash_table_insert(person *p) {
    if (p == NULL) return false;
    
    int index = hash(p->id);
    for (int i = 0; i < TABLE_SIZE; i++) {
        int current_index = (index + i) % TABLE_SIZE;
        
        if (user_hash_table[current_index] == NULL || user_hash_table[current_index] == &deleted_user_entry) {
            user_hash_table[current_index] = p;
            return true;
        }
    }
    return false; // Table full
}

person *user_hash_table_lookup(char *id) {
    int index = hash(id);
    for (int i = 0; i < TABLE_SIZE; i++) {
        int current_index = (index + i) % TABLE_SIZE;
        
        if (user_hash_table[current_index] == NULL) {
            return NULL; // End of probe sequence
        }
        
        if (user_hash_table[current_index] == &deleted_user_entry) {
            continue; // Skip deleted entries
        }
        
        if (strcmp(user_hash_table[current_index]->id, id) == 0) {
            return user_hash_table[current_index];
        }
    }
    return NULL;
}

person *user_hash_table_delete(char *id) {
    int index = hash(id);
    for (int i = 0; i < TABLE_SIZE; i++) {
        int current_index = (index + i) % TABLE_SIZE;

        if (user_hash_table[current_index] == NULL) {
            return NULL; // Not found
        }
        
        if (user_hash_table[current_index] == &deleted_user_entry) {
            continue; // Skip detelted
        }
        
        if (strcmp(user_hash_table[current_index]->id, id) == 0) {
            person *deleted = user_hash_table[current_index];
            user_hash_table[current_index] = &deleted_user_entry;
            return deleted;
        }
    }
    return NULL;
}

//admin hash table
bool admin_hash_table_insert(admin *a) {
    if (a == NULL) return false;
    
    int index = hash(a->id);
    for (int i = 0; i < TABLE_SIZE; i++) {
        int current_index = (index + i) % TABLE_SIZE;
        
        if (admin_hash_table[current_index] == NULL || 
            admin_hash_table[current_index] == &deleted_admin_entry) {
            admin_hash_table[current_index] = a;
            return true;
        }
    }
    return false; // Table full
}

person *admin_hash_table_lookup(char *id) {
    int index = hash(id);
    for (int i = 0; i < TABLE_SIZE; i++) {
        int current_index = (index + i) % TABLE_SIZE;
        
        if (admin_hash_table[current_index] == NULL) {
            return NULL; // End of probe sequence
        }
        
        if (admin_hash_table[current_index] == &deleted_admin_entry) {
            continue; // Skip deleted entries
        }
        
        if (strcmp(admin_hash_table[current_index]->id, id) == 0) {
            return admin_hash_table[current_index];
        }
    }
    return NULL;
}

person *admin_hash_table_delete(char *id) {
    int index = hash(id);
    for (int i = 0; i < TABLE_SIZE; i++) {
        int current_index = (index + i) % TABLE_SIZE;

        if (admin_hash_table[current_index] == NULL) {
            return NULL; // Not found
        }
        
        if (admin_hash_table[current_index] == &deleted_admin_entry) {
            continue; // Skip detelted
        }
        
        if (strcmp(admin_hash_table[current_index]->id, id) == 0) {
            person *deleted = user_hash_table[current_index];
            admin_hash_table[current_index] = &deleted_admin_entry;
            return deleted;
        }
    }
    return NULL;
}

    
//hashing password
void hash_password(const char *password, unsigned char *salt, unsigned char *password_hash) {
    // Generate a random salt
    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        perror("Error generating random bytes.\n");
        return;
    }

    // Concatenate salt and password
    unsigned char salted_password[SALT_SIZE + strlen(password)];
    memcpy(salted_password, salt, SALT_SIZE);
    memcpy(salted_password + SALT_SIZE, password, strlen(password));

    // Hash the salted password
    SHA256(salted_password, sizeof(salted_password), password_hash);
}
//verifying hashed passwords
bool verify_hashed_password(const char *password, unsigned char *salt, unsigned char *password_hash){
    unsigned char salted_password[SALT_SIZE + strlen(password)];
    memcpy(salted_password, salt, SALT_SIZE);
    memcpy(salted_password + SALT_SIZE, password, strlen(password));

    unsigned char new_hash[HASH_SIZE];
    SHA256(salted_password, sizeof(salted_password), new_hash);

    return (memcmp(password_hash, new_hash, HASH_SIZE) == 0);
}

//writing on user file
int user_write_file(){
    FILE *file = fopen(USER_FILE_NAME, "a");
    if (file == NULL)
    {
        perror("Error reading data from files.");
        return 1;
    }

    person *new_user = malloc(sizeof(person));
    if(new_user == NULL){
        perror("Error while allocationg memory to user");
        fclose(file);
        return 1;
    }

    printf("Enter Name: ");
    scanf("%s", new_user->name);
    printf("Enter Surname: ");
    scanf("%s", new_user->surname);
    printf("Enter ID: ");
    scanf("%s", new_user->id);
    printf("Enter Password: ");
    scanf("%s", new_user->password);

    new_user->balance = NEW_USER_BALANCE;

    hash_password(new_user->password, new_user->salt, new_user->password_hash);

    if(hash_table_insert(new_user)){
        printf("User successfuly entered in hash table...\n");
    }
    else{
        printf("Error while putting user in hash table\n");
        free(new_user);
        fclose(file);
        return 1;
    }
    
    fprintf(file, "%s,%s,%s,", new_user->name, new_user->surname, new_user->id);
    
    for (int i = 0; i < SALT_SIZE; i++)
    {
        fprintf(file, "%02x", new_user->salt[i]);
    }

    fprintf(file, ",");

    for (int i = 0; i < HASH_SIZE; i++)
    {
        fprintf(file, "%02x", new_user->password_hash[i]);
    }

    fprintf(file, ",%.2lf\n", new_user->balance);
    
    fclose(file);
    return 0;
}
//writing on admin file
int admin_write_file(){
    FILE *file = fopen(ADMIN_FILE_NAME, "a");
    if (file == NULL)
    {
        perror("Error reading data from files.");
        return 1;
    }

    admin *new_admin = malloc(sizeof(admin));
    if(new_admin == NULL){
        perror("Error while allocationg memory to user");
        fclose(file);
        return 1;
    }

    printf("Enter Name: ");
    scanf("%s", new_admin->name);
    printf("Enter Surname: ");
    scanf("%s", new_admin->surname);
    printf("Enter ID: ");
    scanf("%s", new_admin->id);
    printf("Enter Password: ");
    scanf("%s", new_admin->password);

    hash_password(new_admin->password, new_admin->salt, new_admin->password_hash);

    if(admin_hash_table_insert(new_admin)){
        printf("User successfuly entered in hash table...\n");
    }
    else{
        printf("Error while putting user in hash table\n");
        free(new_user);
        fclose(file);
        return 1;
    }
    
    fprintf(file, "%s,%s,%s,", new_admin->name, new_admin->surname, new_admin->id);
    
    for (int i = 0; i < SALT_SIZE; i++)
    {
        fprintf(file, "%02x", new_admin->salt[i]);
    }

    fprintf(file, ",");

    for (int i = 0; i < HASH_SIZE; i++)
    {
        fprintf(file, "%02x", new_admin->password_hash[i]);
    }

    fprintf(file, ",%.2lf\n", new_admin->balance);
    
    fclose(file);
    return 0;
}
//reading from user file
int user_read_file(){    
    FILE *file = fopen(USER_FILE_NAME, "r");
    if (file == NULL) {
        perror("Error reading data from file.");
        return 1;
    }

    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file) != NULL) {
        person *user = malloc(sizeof(person));
        if (user == NULL) {
            perror("Error during memory allocation!");
            fclose(file);
            return 1;
        }

        char *saveptr;
        char *token = strtok_r(line, ",", &saveptr);
        if (token == NULL) {
            free(user);
            continue;
        }
        strncpy(user->name, token, MAX_NAME);

        token = strtok_r(NULL, ",", &saveptr);
        if (token == NULL) {
            free(user);
            continue;
        }
        strncpy(user->surname, token, MAX_NAME);

        token = strtok_r(NULL, ",", &saveptr);
        if (token == NULL) {
            free(user);
            continue;
        }
        strncpy(user->id, token, MAX_ID);

        token = strtok_r(NULL, ",", &saveptr);
        if (token == NULL) {
            free(user);
            continue;
        }
        for (int i = 0; i < SALT_SIZE; i++) {
            sscanf(token + (i * 2), "%2hhx", &user->salt[i]);
        }

        token = strtok_r(NULL, ",", &saveptr);
        if (token == NULL) {
            free(user);
            continue;
        }
        for (int i = 0; i < HASH_SIZE; i++) {
            sscanf(token + (i * 2), "%2hhx", &user->password_hash[i]);
        }

        token = strtok_r(NULL, ",", &saveptr);
        if (token == NULL) {
            free(user);
            continue;
        }

        user->balance = atof(token);

        if (!user_hash_table_insert(user)) {
            printf("Error while putting user in user hash table\n");
            free(user);
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;
}
//reading from admin file
int admin_read_file(){
    FILE *file = fopen(ADMIN_FILE_NAME, "r");
    if (file == NULL) {
        perror("Error reading data from file.");
        return 1;
    }

    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file) != NULL) {
        admin *admin = malloc(sizeof(person));
        if (admin == NULL) {
            perror("Error during memory allocation!");
            fclose(file);
            return 1;
        }

        char *saveptr;
        char *token = strtok_r(line, ",", &saveptr);
        if (token == NULL) {
            free(admin);
            continue;
        }
        strncpy(admin->name, token, MAX_NAME);

        token = strtok_r(NULL, ",", &saveptr);
        if (token == NULL) {
            free(admin);
            continue;
        }
        strncpy(admin->surname, token, MAX_NAME);

        token = strtok_r(NULL, ",", &saveptr);
        if (token == NULL) {
            free(admin);
            continue;
        }
        strncpy(admin->id, token, MAX_ID);

        token = strtok_r(NULL, ",", &saveptr);
        if (token == NULL) {
            free(admin);
            continue;
        }
        for (int i = 0; i < SALT_SIZE; i++) {
            sscanf(token + (i * 2), "%2hhx", &admin->salt[i]);
        }

        token = strtok_r(NULL, ",", &saveptr);
        if (token == NULL) {
            free(admin);
            continue;
        }
        for (int i = 0; i < HASH_SIZE; i++) {
            sscanf(token + (i * 2), "%2hhx", &admin->password_hash[i]);
        }

        if (!admin_hash_table_insert(admin)) {
            printf("Error while putting user in admin hash table\n");
            free(admin);
            fclose(admin);
            return 1;
        }
    }
    fclose(file);
    return 0;
}

//welcome menu
int welcome_menu(){
    printf("Welcome to the banking system\n");
    printf("Choose below:/n/n");
    printf("1. Login as user\n");
    printf("2. Login as administrator\n")
    pritnf("3. Exit");
}
//user menu
void user_menu(){
    printf("Check Account Balance\n");
    printf("Check personal info");
    printf("Set Transaction\n");
    printf("Exit\n");
}
//admin menu
void admin_menu(){
    printf("Insert a user");
    printf("Delete a user");
    printf("Lookup a user");
    printf("Exit");
}

//logging users
bool login_user(char *id, char *password){
    int attempts = 0;
    int choice = 0;

    while (attempts < MAX_LOGIN_ATTEMPTS)
    {
        printf("---Login---\n");

        printf("Enter ID: ");
        scanf("%s", id);

        printf("Enter password: ");
        scanf("%s", password);

        person *user = user_hash_table_lookup(id);

        if(user == NULL){
            printf("The user ID '%s' does not exist! (you have %d attempts left)\n", id, MAX_LOGIN_ATTEMPTS-(attempts+1));
            attempts++;
            continue;
        }

        if(verify_hashed_password(password, user->salt, user->password_hash)){
            printf("Welcome back %s!\n", user->name);
            return true;
        }
        else{
            printf("Password is incorrect (you have %d attempts left)", MAX_LOGIN_ATTEMPTS-(attempts+1));
            attempts++;
        }
    }
    printf("You reached the maximum attempts, please try again later!\n");
    return false;
}
//logging admins
bool login_admin(char *id, char *password){
    int attempts = 0;
    int choice = 0;

    while (attempts < MAX_LOGIN_ATTEMPTS)
    {
        printf("---Login---\n");

        printf("Enter ID: ");
        scanf("%s", id);

        printf("Enter password: ");
        scanf("%s", password);

        admin *admin = admin_hash_table_lookup(id);

        if(admin == NULL){
            printf("The admin ID '%s' does not exist! (you have %d attempts left)\n", id, MAX_LOGIN_ATTEMPTS-(attempts+1));
            attempts++;
            continue;
        }

        if(verify_hashed_password(password, admin->salt, admin->password_hash)){
            printf("Welcome back %s!\n", admin->name);
            return true;
        }
        else{
            printf("Password is incorrect (you have %d attempts left)", MAX_LOGIN_ATTEMPTS-(attempts+1));
            attempts++;
        }
    }
    printf("You reached the maximum attempts, please try again later!\n");
    return false;
}



void clean_hash(){
        for (int i = 0; i < TABLE_SIZE; i++) {
        person *p = user_hash_table[i];
        admin *a = admin_hash_table[i];
        if (p != NULL && p != &deleted_user_entry) {
            free(p);
            user_hash_table[i] = NULL;
        }
        if (a != NULL && a != &deleted_admin_entry) {
            free(a);
            admin_hash_table[i] = NULL;
        }
    }
}

int main() {
    init_hash_table();
    atexit(clean_hash);
    char id[MAX_ID];
    char password[MAX_PASSWORD_LENGTH];
    int choice = 0;

    welcome_menu();
    while (1)
    {
        printf("Enter your choice: ");
        scanf("%d", &choice);
        switch (choice)
        {
            case 1:
                if (user_read_file() != 0){
                    perror("Error reading files!\n");
                    return 1;
                }

                if (login_user(id, password) == false)
                {
                    return 1;
                }
                
                user_menu();

                break;
            case 2:
                if (user_read_file() != 0 || admin_read_file() != 0){
                    perror("Error reading files!\n");
                    return 1;
                }

                if (login_admin(id, password) == false)
                {
                    return 1;
                }

                admin_menu();

                break;
            case 3: 
                printf("Exiting... \n");
                return 0;
            default: printf("Your choice is out of the range\n");
        }
    }

    return 0;
}