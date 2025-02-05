//gcc -o myprogram hash.c -I$(brew --prefix openssl)/include -L$(brew --prefix openssl)/lib -lssl -lcrypto
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#define MAX_NAME 256
#define TABLE_SIZE 10
#define MAX_ID 20
#define MAX_PASSWORD_LENGTH 20
#define FILE_NAME "bankfile.csv"
#define MAX_LINE_LENGTH 256
#define NEW_USER_BALANCE 50.0

#define SALT_SIZE 16
#define HASH_SIZE 32

typedef struct person {
    char name[MAX_NAME];
    char surname[MAX_NAME];
    char id[MAX_ID];
    char username[MAX_NAME];
    char password[MAX_PASSWORD_LENGTH];
    unsigned char salt[SALT_SIZE];
    unsigned char password_hash[HASH_SIZE];
    double balance;
} person;

typedef struct employee{
    char name[MAX_NAME];
    char surname[MAX_NAME];
    char id[MAX_ID];
    char username[MAX_NAME];
    char password[MAX_PASSWORD_LENGTH];
    unsigned char salt[SALT_SIZE];
    unsigned char password_hash[HASH_SIZE];
} admin;

//necessary functions for hashing by id
person *hash_table[TABLE_SIZE];
person deleted_entry = {.id = ""}; // Marker for deleted entries
unsigned int hash(char *id) {
    unsigned long hash = 5381;
    int c;
    while ((c = *id++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash % TABLE_SIZE;
}
void init_hash_table() {
    for (int i = 0; i < TABLE_SIZE; i++) {
        hash_table[i] = NULL;
    }
}
void print_table() {
    printf("Start\n");
    for (int i = 0; i < TABLE_SIZE; i++) {
        printf("\t%d| ", i);
        if (hash_table[i] == NULL) {
            printf("----\n");
        } else if (hash_table[i] == &deleted_entry) {
            printf("<deleted>\n");
        } else {
            printf("%s\n", hash_table[i]->name);
        }
    }
    printf("End\n");
}
bool hash_table_insert(person *p) {
    if (p == NULL) return false;
    
    int index = hash(p->id);
    for (int i = 0; i < TABLE_SIZE; i++) {
        int current_index = (index + i) % TABLE_SIZE;
        
        if (hash_table[current_index] == NULL || 
            hash_table[current_index] == &deleted_entry) {
            hash_table[current_index] = p;
            return true;
        }
    }
    return false; // Table full
}
person *hash_table_lookup(char *id) {
    int index = hash(id);
    for (int i = 0; i < TABLE_SIZE; i++) {
        int current_index = (index + i) % TABLE_SIZE;
        
        if (hash_table[current_index] == NULL) {
            return NULL; // End of probe sequence
        }
        
        if (hash_table[current_index] == &deleted_entry) {
            continue; // Skip deleted entries
        }
        
        if (strcmp(hash_table[current_index]->id, id) == 0) {
            return hash_table[current_index];
        }
    }
    return NULL;
}
person *hash_table_delete(char *id) {
    int index = hash(id);
    for (int i = 0; i < TABLE_SIZE; i++) {
        int current_index = (index + i) % TABLE_SIZE;
        
        if (hash_table[current_index] == NULL) {
            return NULL; // Not found
        }
        
        if (hash_table[current_index] == &deleted_entry) {
            continue; // Skip detelted
        }
        
        if (strcmp(hash_table[current_index]->id, id) == 0) {
            person *deleted = hash_table[current_index];
            hash_table[current_index] = &deleted_entry;
            return deleted;
        }
    }
    return NULL;
}

//hashing password
void hash_password(const char *password, unsigned char *salt, unsigned char *password_hash) {
    // Generate a random salt
    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        fprintf(stderr, "Error generating random bytes.\n");
        return;
    }

    // Concatenate salt and password
    unsigned char salted_password[SALT_SIZE + strlen(password)];
    memcpy(salted_password, salt, SALT_SIZE);
    memcpy(salted_password + SALT_SIZE, password, strlen(password));

    // Hash the salted password
    SHA256(salted_password, sizeof(salted_password), hash);
}
bool verify_hashed_password(const char *password, unsigned char *salt, unsigned char *password_hash){
    unsigned char salted_password[SALT_SIZE = strlen(password)];
    memcpy(salted_password, salt, SALT_SIZE);
    memcpy(salted_password + SALT_SIZE, password, strlen(password));

    unsigned char new_hash[HASH_SIZE];
    SHA256(salted_password, sizeof(salted_password), new_hash);

    if (memcmp(hash, new_hash, HASH_SIZE) == 0)
    {
        return true;
    }
    return false;
    
}


int write_file(){
    FILE *file = fopen(FILE_NAME, "a");
    if (file == NULL)
    {
        perror("Error reading data from files.");
        return 1;
    }

    person *new_user = malloc(sizeof(person));
    if(new_user == NULL){
        perror("Error while allocationg memory to user");
        return 1;
    }

    printf("Enter Name: ");
    scanf("%s", new_user->name);
    printf("Enter Surname: ");
    scanf("%s", new_user->surname);
    printf("Enter ID: ");
    scanf("%s", new_user->id);
    printf("Enter Username: ");
    scanf("%s", new_user->username);
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
    
    fprintf("%s,%s,%s,%s,%s,%s\n",new_user->name, new_user->surname, new_user->id, new_user->username, new_user->password_hash, new_user->balance);

    free(new_user);
    fclose(file);
    return 0;
}
int read_file(){
    FILE *file = fopen(FILE_NAME, "r");
    if (file == NULL)
    {
        perror("Error reading data from files.");
        return 1;
    }

    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file) != NULL)
    {
        person *user = malloc(sizeof(person));
        if (user == NULL)
        {
            perror("Error during memory allocation!");
            return 1;
        }

        char *token = strtok(line, ",");
        if(token != NULL){
            strncpy(user->name, token, sizeof(user->name)-1);
            user->name[sizeof(user->name)-1] = '\0';
        }
        char *token = strtok(line, ",");
        if(token != NULL){
            strncpy(user->surname, token, sizeof(user->surname)-1);
            user->surname[sizeof(user->surname)-1] = '\0';
        }
        char *token = strtok(line, ",");
        if(token != NULL){
            strncpy(user->id, token, sizeof(user->id)-1);
            user->id[sizeof(user->id)-1] = '\0';
        }
        char *token = strtok(line, ",");
        if(token != NULL){
            strncpy(user->username, token, sizeof(user->username)-1);
            user->username[sizeof(user->username)-1] = '\0';
        }
        char *token = strtok(line, ",");
        if(token != NULL){
            strncpy(user->password_hash, token, sizeof(user->password_hash)-1);
            user->password_hash[sizeof(user->password_hash)-1] = '\0';
        }
        char *token = strtok(line, ",");
        if(token != NULL){
            strncpy(user->balance, token, sizeof(user->balance)-1);
            user->balance[sizeof(user->balance)-1] = '\0';
        }

        if(hash_table_insert(user)){
            printf("User successfuly entered in hash table...\n");
        }

        else{
            printf("Error while putting user in hash table\n");
            free(user);
            fclose(file);
            return 1;
        }
    } 
    fclose(file);
    return 0;
}

void user_menu(){
    printf("Check Account Balance\n");
    printf("Set Transaction\n");
    printf("Exit\n");
}

bool login_user(){
    read_file();
    printf("Welcome to the Banking System\n\n");

    printf("---Login---\n");
    printf("Enter username: ");
    scanf("%s", )
}


int main() {
    init_hash_table();
        
    admin *ADMINISTRATOR = {.name = "Matthias", .surname = "Mifsud", .id = "0001A", .username = "BankAdmin", .password = "VeryStrongPassword"};
    hash_password(ADMINISTRATOR->password, ADMINISTRATOR->salt, ADMINISTRATOR->password_hash);

    user_menu();

    while (true)
    {
        switch ()
        {
            case 1:
                
                break;
    
            case 2:
                
                break;

            case 3:
                printf("Exiting...");
                exit(0);
                break
    
            default:
                printf("Your choice does not within the required range\n");
        } 
    }
    return 0;
}