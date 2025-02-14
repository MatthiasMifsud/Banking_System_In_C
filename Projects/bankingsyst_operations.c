#include "bankingsyst_head.h"

//necessary functions for hashing by id
person *user_hash_table[TABLE_SIZE];
person deleted_user_entry = {.id = ""}; // Marker for deleted entries

administrator *admin_hash_table[TABLE_SIZE];
administrator deleted_admin_entry = {.id = ""}; // Marker for deleted entries

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

//insert user
bool user_hash_table_insert(person *user) {
    if (user == NULL) return false;
    
    int index = hash(user->id);
    for (int i = 0; i < TABLE_SIZE; i++) {
        int current_index = (index + i) % TABLE_SIZE;
        
        if (user_hash_table[current_index] == NULL || user_hash_table[current_index] == &deleted_user_entry) {
            user_hash_table[current_index] = user;
            return true;
        }
    }
    return false; // Table full
}
//lookup user
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
//delete user
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

//insert admin
bool admin_hash_table_insert(administrator *admin) {
    if (admin == NULL) return false;
    
    int index = hash(admin->id);
    for (int i = 0; i < TABLE_SIZE; i++) {
        int current_index = (index + i) % TABLE_SIZE;
        
        if (admin_hash_table[current_index] == NULL || 
            admin_hash_table[current_index] == &deleted_admin_entry) {
            admin_hash_table[current_index] = admin;
            return true;
        }
    }
    return false; // Table full
}
//lookup admin
administrator *admin_hash_table_lookup(char *id) {
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
//delete admin
administrator *admin_hash_table_delete(char *id) {
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
            administrator *deleted = admin_hash_table[current_index];
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
        perror("ERROR reading data from files.");
        return 1;
    }

    person *new_user = malloc(sizeof(person));
    if(new_user == NULL){
        perror("ERROR while allocationg memory to user.");
        fclose(file);
        return 1;
    }

    printf("Enter User's Name: ");
    scanf("%255s", new_user->name);
    if(strlen(new_user->name) == 0){
        printf(" ------------------------------\n");
        printf("| ERROR: Name cannot be empty! |\n");
        printf("|______________________________|\n\n");
        free(new_user);
        fclose(file);
        return 1;
    }
    else if(strlen(new_user->name) >= MAX_NAME){
        printf(" -------------------------------------------\n");
        printf("| ERROR: Name cannot exceed %d characters! |\n", MAX_NAME-1);
        printf("|___________________________________________|\n\n");
        free(new_user);
        fclose(file);
        return 1;
    }
    printf("------------------------------------------\n");


    printf("Enter User's Surname: ");
    scanf("%255s", new_user->surname);
    if(strlen(new_user->surname) == 0){
        printf(" ---------------------------------\n");
        printf("| ERROR: Surname cannot be empty! |\n");
        printf("|_________________________________|\n\n");
        free(new_user);
        fclose(file);
        return 1;
    }
    else if(strlen(new_user->surname) >= MAX_NAME){
        printf(" ----------------------------------------------\n");
        printf("| ERROR: Surname cannot exceed %d characters! |\n", MAX_NAME-1);
        printf("|______________________________________________|\n\n");
        free(new_user);
        fclose(file);
        return 1;
    }
    printf("------------------------------------------\n");

    printf("Enter User's ID: ");
    scanf("%99s", new_user->id);
    if(strlen(new_user->id) == 0){
        printf(" ----------------------------\n");
        printf("| ERROR: ID cannot be empty! |\n");
        printf("|____________________________|\n\n");
        free(new_user);
        fclose(file);
        return 1;
    }
    else if(strlen(new_user->id) >= MAX_ID){
        printf(" ----------------------------------------\n");
        printf("| ERROR: ID cannot exceed %d characters! |\n", MAX_ID-1);
        printf("|________________________________________|\n\n");
        free(new_user);
        fclose(file);
        return 1;
    }
    else if(user_hash_table_lookup(new_user->id) != NULL){
        printf(" -------------------------------------\n");
        printf("| ERROR: This user ID already exists! |\n");
        printf("|_____________________________________|\n\n");
        free(new_user);
        fclose(file);
        return 1;
    }
    printf("------------------------------------------\n");

    printf("Enter User's Password: ");
    scanf("%99s", new_user->password);
    if(strlen(new_user->password) == 0){
        printf(" ----------------------------------\n");
        printf("| ERROR: Password cannot be empty! |\n");
        printf("|__________________________________|\n\n");
        free(new_user);
        fclose(file);
        return 1;
    }
    else if(strlen(new_user->password) >= MAX_PASSWORD_LENGTH){
        printf(" ---------------------------------------------\n");
        printf("| ERROR: Password cannot exceed %d characters |\n", MAX_PASSWORD_LENGTH-1);
        printf("|_____________________________________________|\n\n");
        free(new_user);
        fclose(file);
        return 1;
    }
    printf("------------------------------------------\n");

    printf("Enter User's Balance: ");
    if(scanf("%lf", &new_user->balance) != 1){
        printf(" -------------------------------------\n");
        printf("| ERROR: Balance can only be numeric! |\n");
        printf("|_____________________________________|\n\n");
        free(new_user);
        fclose(file);
        return 1;
    }
    printf("------------------------------------------\n\n");
    

    hash_password(new_user->password, new_user->salt, new_user->password_hash);

    if(!user_hash_table_insert(new_user)){
        printf(" -----------------------------------------\n");
        printf("| Error while putting user in hash table. |\n");
        printf("|_________________________________________|\n\n");
        free(new_user);
        fclose(file);
        return 1;
    }
    
    fprintf(file, "%s,%s,%s,", new_user->name, new_user->surname, new_user->id);
    
    for (int i = 0; i < SALT_SIZE; i++) fprintf(file, "%02x", new_user->salt[i]);

    fprintf(file, ",");

    for (int i = 0; i < HASH_SIZE; i++) fprintf(file, "%02x", new_user->password_hash[i]);

    fprintf(file, ",%.2lf\n", new_user->balance);
    
    fclose(file);


    char filename[MAX_ID + 5];
    snprintf(filename, sizeof(filename), "transactions/%s.csv", new_user->id);

    FILE *file_transaction = fopen(filename, "a");
    if (file_transaction == NULL) {
        perror("Error opening file.");
        return 1;
    }

    fprintf(file_transaction, "$%.2lf was initilised to your account (Current balance: %.2lf).\n", new_user->balance, new_user->balance);

    fclose(file_transaction);

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

    administrator *new_admin = malloc(sizeof(administrator));
    if(new_admin == NULL){
        perror("Error while allocationg memory to user");
        fclose(file);
        return 1;
    }

    printf("Enter Admin's Name: ");
    scanf("%255s", new_admin->name);
    if(strlen(new_admin->name) == 0){
        printf(" ------------------------------\n");
        printf("| ERROR: Name cannot be empty! |\n");
        printf("|______________________________|\n\n");
        free(new_admin);
        fclose(file);
        return 1;
    }
    else if(strlen(new_admin->name) >= MAX_NAME){
        printf(" -------------------------------------------\n");
        printf("| ERROR: Name cannot exceed %d characters! |\n", MAX_NAME-1);
        printf("|___________________________________________|\n\n");
        free(new_admin);
        fclose(file);
        return 1;
    }
    printf("------------------------------------------\n");


    printf("Enter Admin's Surname: ");
    scanf("%255s", new_admin->surname);
    if(strlen(new_admin->surname) == 0){
        printf(" ---------------------------------\n");
        printf("| ERROR: Surname cannot be empty! |\n");
        printf("|_________________________________|\n\n");
        free(new_admin);
        fclose(file);
        return 1;
    }
    else if(strlen(new_admin->surname) >= MAX_NAME){
        printf(" ----------------------------------------------\n");
        printf("| ERROR: Surname cannot exceed %d characters! |\n", MAX_NAME-1);
        printf("|______________________________________________|\n\n");
        free(new_admin);
        fclose(file);
        return 1;
    }
    printf("------------------------------------------\n");

    printf("Enter Admin's ID: ");
    scanf("%99s", new_admin->id);
    if(strlen(new_admin->id) == 0){
        printf(" ----------------------------\n");
        printf("| ERROR: ID cannot be empty! |\n");
        printf("|____________________________|\n\n");
        free(new_admin);
        fclose(file);
        return 1;
    }
    else if(admin_hash_table_lookup(new_admin->id) != NULL){
        printf(" -------------------------------------\n");
        printf("| ERROR: This admin ID already exists! |\n");
        printf("|______________________________________|\n\n");
        free(new_admin);
        fclose(file);
        return 1;
    }
    printf("------------------------------------------\n");

    printf("Enter Admin's Password: ");
    scanf("%99s", new_admin->password);
    if(strlen(new_admin->password) == 0){
        printf(" ----------------------------------\n");
        printf("| ERROR: Password cannot be empty! |\n");
        printf("|__________________________________|\n\n");
        free(new_admin);
        fclose(file);
        return 1;
    }
    else if(strlen(new_admin->password) >= MAX_PASSWORD_LENGTH){
        printf(" ----------------------------------------------\n");
        printf("| ERROR: Password cannot exceed %d characters! |\n", MAX_PASSWORD_LENGTH-1);
        printf("|______________________________________________|\n\n");
        free(new_admin);
        fclose(file);
        return 1;
    }
    printf("------------------------------------------\n\n");

    hash_password(new_admin->password, new_admin->salt, new_admin->password_hash);

    if(!admin_hash_table_insert(new_admin)){
        printf(" -----------------------------------------\n");
        printf("| ERROR while putting user in hash table! |\n");
        printf("|_________________________________________|\n\n");
        free(new_admin);
        fclose(file);
        return 1;
    }
    
    fprintf(file, "%s,%s,%s,", new_admin->name, new_admin->surname, new_admin->id);
    
    for (int i = 0; i < SALT_SIZE; i++) fprintf(file, "%02x", new_admin->salt[i]);

    fprintf(file, ",");

    for (int i = 0; i < HASH_SIZE; i++) fprintf(file, "%02x", new_admin->password_hash[i]);

    fprintf(file, "\n");
    
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
            printf(" -----------------------------------------\n");
            printf("| Error while putting user in hash table! |\n");
            printf("|_________________________________________|\n\n");
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
        administrator *admin = malloc(sizeof(administrator));
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
            printf(" ------------------------------------------\n");
            printf("| Error while putting admin in hash table! |\n");
            printf("|__________________________________________|\n\n");
            free(admin);
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;
}
//updating user file
void user_update_file(){
    FILE *file = fopen(USER_FILE_NAME, "w");

    for (int i = 0; i < TABLE_SIZE; i++)
    {
        if (user_hash_table[i] != NULL && user_hash_table[i] != &deleted_user_entry) {
            person *user = user_hash_table[i];

            fprintf(file, "%s,%s,%s,", user->name, user->surname, user->id);

            for (int j = 0; j < SALT_SIZE; j++) fprintf(file, "%02x", user->salt[j]);

            fprintf(file, ",");

            for (int j = 0; j < HASH_SIZE; j++) fprintf(file, "%02x", user->password_hash[j]);

            fprintf(file, ",%.2lf\n", user->balance);
        }
    }
    fclose(file);
}
//updating admin file
void admin_update_file(){
    FILE *file = fopen(ADMIN_FILE_NAME, "w");

    for (int i = 0; i < TABLE_SIZE; i++)
    {
        if (admin_hash_table[i] != NULL && admin_hash_table[i] != &deleted_admin_entry) {
            administrator *admin = admin_hash_table[i];

            fprintf(file, "%s,%s,%s,", admin->name, admin->surname, admin->id);

            for (int j = 0; j < SALT_SIZE; j++) fprintf(file, "%02x", admin->salt[j]);

            fprintf(file, ",");

            for (int j = 0; j < HASH_SIZE; j++) fprintf(file, "%02x", admin->password_hash[j]);

        }
    }
    fclose(file);
}

//logging users
bool login_user(char *id, char *password){
    int attempts = 0;
    int choice = 0;

    while (attempts < MAX_LOGIN_ATTEMPTS)
    {
        printf("\n============================================\n\n");
        printf(" ----------------------------------------\n");
        printf("|                  LOGIN                 |\n");
        printf("|________________________________________|\n\n");

        printf("Enter ID: "); 
        scanf("%s", id);
        printf("----------------------------------------\n");
        printf("Enter password: ");
        scanf("%s", password);
        printf("----------------------------------------\n\n");    

        person *user = user_hash_table_lookup(id);

        if(user == NULL){
            printf(" ---------------------------------------------------------\n");
            printf("| This user ID does not exist! (you have %d attempts left) |\n", MAX_LOGIN_ATTEMPTS-(attempts+1));
            printf("|_________________________________________________________|\n");
            attempts++;
            continue;
        }

        if(verify_hashed_password(password, user->salt, user->password_hash)){
            printf(" ----------------------------------------\n");
            printf("| Welcome back %-23s:) |\n", user->name);
            printf("|________________________________________|\n\n");
            return true;
        }
        else{
            printf(" --------------------------------------------------\n");
            printf("| Password is incorrect (you have %d attempts left) |\n", MAX_LOGIN_ATTEMPTS-(attempts+1));
            printf("|__________________________________________________|\n");

            attempts++;
        }
    }
    printf(" -----------------------------------------------------------\n");
    printf("| You reached the maximum attempts, please try again later! |\n");
    printf("|___________________________________________________________|\n");
    return false;
}
//logging admins
bool login_admin(char *id, char *password){
    int attempts = 0;
    int choice = 0;

    while (attempts < MAX_LOGIN_ATTEMPTS)
    {
        printf(" ----------------------------------------\n");
        printf("|                  LOGIN                 |\n");
        printf(" ----------------------------------------\n\n");

        printf("Enter ID: "); 
        scanf("%s", id);
        printf("----------------------------------------\n");
        printf("Enter password: ");
        scanf("%s", password);
        printf("----------------------------------------\n\n");
        
        administrator *admin = admin_hash_table_lookup(id);

        if(admin == NULL){
            printf(" ---------------------------------------------------------\n");
            printf("| This admin ID does not exist! (you have %d attempts left)|\n", MAX_LOGIN_ATTEMPTS-(attempts+1));
            printf("|_________________________________________________________|\n");

            attempts++;
            continue;
        }

        if(verify_hashed_password(password, admin->salt, admin->password_hash)){
            printf(" ----------------------------------------\n");
            printf("| Welcome back %-23s:) |\n", admin->name);
            printf("|________________________________________|\n");

            return true;
        }
        else{
            printf(" --------------------------------------------------\n");
            printf("| Password is incorrect (you have %d attempts left) |", MAX_LOGIN_ATTEMPTS-(attempts+1));
            printf("|__________________________________________________|\n");

            attempts++;
        }
    }
    printf(" -----------------------------------------------------------\n");
    printf("| You reached the maximum attempts, please try again later! |\n");
    printf("|___________________________________________________________|\n");
    return false;
}

//cheking user current balance
void check_user_balance(person *current_user){
    printf(" ----------------------------------------\n");
    printf("| Current Balance: $%-20.2lf |\n", current_user->balance);
    printf("|________________________________________|\n\n");
}
//checking user personal info
void user_personal_info(person *current_user, const char *password){
    printf(" --------------------------------------------------------------------------------------------------------------\n");
    printf("|                                           User Personal Information                                          |\n");
    printf("|==============================================================================================================|\n");
    printf("|         Name         |       Surname        |          ID          |       Password       | Current Balance  |\n");
    printf("|----------------------|----------------------|----------------------|----------------------|------------------|\n");
    printf("| %-20s | %-20s | %-20s | %-20s | $%-15.2lf |\n", current_user->name, current_user->surname, current_user->id, password, current_user->balance);
    printf("|______________________________________________________________________________________________________________|\n\n");
}
//performing transactions between users
void setting_transactions(person *current_user){

    char receiver_id[MAX_ID];
    double amount;

    printf("Select ID of the user you wish to send a transaction to: ");
    scanf("%99s", receiver_id);
    
    if(strcmp(receiver_id, current_user->id) == 0){
        printf(" ---------------------------------------\n");
        printf("| ERROR: You cannot choose your own ID! |\n");
        printf("|_______________________________________|\n\n");
        return;
    }
    else if(strlen(receiver_id) == 0){
        printf(" ----------------------------\n");
        printf("| ERROR: ID cannot be empty! |\n");
        printf("|____________________________|\n\n");
        return ;
    }
    else if(strlen(receiver_id) >= MAX_ID){
        printf(" ----------------------------------------\n");
        printf("| ERROR: ID cannot exceed %d characters! |\n", MAX_ID-1);
        printf("|________________________________________|\n\n");
        return;
    }
    else if(user_hash_table_lookup(receiver_id) == NULL){
        printf(" --------------------------------\n");
        printf("| ERROR: This ID does not exist! |\n");
        printf("|________________________________|\n\n");
        return;
    }

    printf("------------------------------------------------------------\n");

    person *receiver_user = user_hash_table_lookup(receiver_id);

    printf("Select the amount you wish to send to the User '%s': ", receiver_id);
    if(scanf("%lf", &amount) != 1){
        printf(" ------------------------------------\n");
        printf("| ERROR: Amount can only be numeric! |\n");
        printf("|____________________________________|\n\n");
        return;
    }
    else if(amount > current_user->balance){
        printf(" ---------------------------------------------------------------\n");
        printf("| ERROR: The amount you wish to send EXCEEDS your bank balance! |\n");
        printf("|_______________________________________________________________|\n\n");
        return;
    }
    else if(amount <= 0){
        printf(" ---------------------------------------------------------------\n");
        printf("| ERROR: The amount you wish to send CANNOT be negative nor $0! |\n");
        printf("|_______________________________________________________________|\n\n");
        return;
    }

    printf("------------------------------------------------------------\n");

    while(1){
        printf("Are you sure you wish to send $%.2lf to user '%s'? (y/n): ", amount, receiver_id);

        char choice;
        
        if (scanf(" %c", &choice) != 1){
            printf("\n ----------------------------------------------\n");
            printf("| ERROR: Choice can only be of character type! |\n");
            printf("|______________________________________________|\n\n");
        }
        else if (choice == 'n' || choice == 'N'){
            printf("\n ------------\n");
            printf("| Exiting... |\n");
            printf("|____________|\n\n");
            return;
        }
        else if (choice == 'y' || choice == 'Y'){
            break;
        }
        printf("\n --------------------------------------\n");
        printf("| ERROR: Choice can only be 'y' or 'n' |\n");
        printf("|______________________________________|\n\n");
    }
    current_user->balance -= amount;
    receiver_user->balance += amount;
    user_update_file();

    char filename_from[MAX_ID + 5];
    char filename_to[MAX_ID + 5];
    snprintf(filename_from, sizeof(filename_from), "transactions/%s.csv", current_user->id);
    snprintf(filename_to, sizeof(filename_to), "transactions/%s.csv", receiver_id);

    FILE *file_from = fopen(filename_from, "a");
    FILE *file_to = fopen(filename_to, "a");
    if (file_from == NULL || file_to == NULL) {
        perror("Error opening file.");
        return;
    }

    fprintf(file_from, "You passed a transaction of $%.2lf to user '%s' (Current balance: %.2lf).\n", amount, receiver_id, current_user->balance);
    fprintf(file_to, "You received a transaction of $%.2lf from user '%s' (Current balance: %.2lf).\n", amount, current_user->id, receiver_user->balance);

    fclose(file_from);
    fclose(file_to);
}
//reading transaction history
void read_transaction_file(char *id) {
    char filename[MAX_ID + 5];
    snprintf(filename, sizeof(filename), "transactions/%s.csv", id);
    FILE *file = fopen(filename, "r");
    
    if (file == NULL) {
        perror("Error opening file.");
        return;
    }

    char line[256];
    int count = 1;
    printf("Transaction History for User '%s':\n", id);
    printf("-----------------------------------------------------------------------------------------------------\n");

    while (fgets(line, sizeof(line), file) != NULL) {
        printf("| %d. %s", count, line);
        count++;
    }
    printf("|____________________________________________________________________________________________________\n\n");
    fclose(file);
}
//deleting users
void delete_user(){
    char delete_user_id[MAX_ID];

    printf("Enter ID of user you wish to remove: ");
    scanf("%s", delete_user_id);

    if(strlen(delete_user_id) == 0){
        printf(" ----------------------------\n");
        printf("| ERROR: ID cannot be empty! |\n");
        printf("|____________________________|\n\n");
        return;
    }
    else if(strlen(delete_user_id) >= MAX_ID){
        printf(" ----------------------------------------\n");
        printf("| ERROR: ID cannot exceed %d characters! |\n", MAX_ID-1);
        printf("|________________________________________|\n\n");
        return;
    }
    else if(user_hash_table_lookup(delete_user_id) == NULL){
        printf(" --------------------------------------\n");
        printf("| ERROR: This user ID does not exists! |\n");
        printf("|______________________________________|\n\n");
        return;
    }

    person *user_to_delete = user_hash_table_lookup(delete_user_id);
    char password_empty[] = "NON VISIBLE";
    user_personal_info(user_to_delete, password_empty);

    while(1){
        printf("Are you sure you wish to delete this user? (y/n): ");
        
        char choice;
        if (scanf(" %c", &choice) != 1){
            printf("\n ----------------------------------------------\n");
            printf("| ERROR: Choice can only be of character type! |\n");
            printf("|______________________________________________|\n\n");
        }
        else if (choice == 'n' || choice == 'N'){
            printf("\n ------------\n");
            printf("| Exiting... |\n");
            printf("|____________|\n\n");
            return;
        }
        else if (choice == 'y' || choice == 'Y'){
            break;
        }
        printf("\n -------------------------------\n");
        printf("| Choice can only be 'y' or 'n' |\n");
        printf("|_______________________________|\n\n");
    }
    user_hash_table_delete(delete_user_id);
    user_update_file();

    char transaction_file[MAX_ID + 5];
    snprintf(transaction_file, sizeof(transaction_file), "transactions/%s.csv", delete_user_id);

    if (remove(transaction_file) != 0) {
        perror("Error deleting file");
        return;
    }
}
//lookup user
void lookup_users(){
    char lookup_id[MAX_ID];

    printf("Enter ID of user you wish to lookup: ");
    scanf("%s", lookup_id);

    printf("\n");

    if(strlen(lookup_id) == 0){
        printf(" ----------------------------\n");
        printf("| ERROR: ID cannot be empty! |\n");
        printf("|____________________________|\n\n");
        return;
    }
    else if(strlen(lookup_id) >= MAX_ID){
        printf(" ----------------------------------------\n");
        printf("| ERROR: ID cannot exceed %d characters! |\n", MAX_ID-1);
        printf("|________________________________________|\n\n");
        return;
    }
    else if(user_hash_table_lookup(lookup_id) == NULL){
        printf(" --------------------------------------\n");
        printf("| ERROR: This user ID does not exists! |\n");
        printf("|______________________________________|\n\n");
        return;
    }

    person *lookup_user = user_hash_table_lookup(lookup_id);
    char password_empty[] = "NON VISIBLE";
    user_personal_info(lookup_user, password_empty);
    printf("\n");
    read_transaction_file(lookup_id);
}
//list users
void list_users(){
    char password[] = "NOT VISIBLE";
    printf(" --------------------------------------------------------------------------------------------------------------\n");
    printf("|                                           User Personal Information                                          |\n");
    printf("|==============================================================================================================|\n");
    printf("|         Name         |       Surname        |          ID          |       Password       | Current Balance  |\n");
    printf("|----------------------|----------------------|----------------------|----------------------|------------------|\n");

    for (int i = 0; i < TABLE_SIZE; i++)
    {
        if (user_hash_table[i] != NULL && user_hash_table[i] != &deleted_user_entry) {
            person *user = user_hash_table[i];
            printf("| %-20s | %-20s | %-20s | %-20s | $%-15.2lf |\n", user->name, user->surname, user->id, password, user->balance);
        }
    }
    printf("|______________________________________________________________________________________________________________|\n\n");
}
//cheking personl info of admin
void admin_personal_info(administrator *currents_admin, const char *password){
    printf(" -------------------------------------------------------------------------------------------\n");
    printf("|                                 Admin Personal Information                                |\n");
    printf("|===========================================================================================|\n");
    printf("|         Name         |       Surname        |          ID          |       Password       |\n");
    printf("|----------------------|----------------------|----------------------|----------------------|\n");
    printf("| %-20s | %-20s | %-20s | %-20s |\n", currents_admin->name, currents_admin->surname, currents_admin->id, password);
    printf("|___________________________________________________________________________________________|\n\n");
}
//delete admins
void delete_admin(){
    char delete_admin_id[MAX_ID];
    char choice;

    printf("Enter ID of admin you wish to remove: ");
    scanf("%s", delete_admin_id);

    if(strlen(delete_admin_id) == 0){
        printf(" ----------------------------\n");
        printf("| ERROR: ID cannot be empty! |\n");
        printf("|____________________________|\n\n");
        return;
    }
    else if(strlen(delete_admin_id) >= MAX_ID){
        printf(" ----------------------------------------\n");
        printf("| ERROR: ID cannot exceed %d characters! |\n", MAX_ID-1);
        printf("|________________________________________|\n\n");
        return;
    }
    else if(admin_hash_table_lookup(delete_admin_id) == NULL){
        printf(" ---------------------------------------\n");
        printf("| ERROR: This admin ID does not exists! |\n");
        printf("|_______________________________________|\n\n");
        return;
    }

    administrator *admin_to_delete = admin_hash_table_lookup(delete_admin_id);
    char password_empty[] = "NON VISIBLE";
    admin_personal_info(admin_to_delete, password_empty);

    while(1){
        printf("Are you sure you wish to delete this admin? (y/n): ");

        if (scanf(" %c", &choice) != 1){
            printf("\n ----------------------------------------------\n");
            printf("| ERROR: Choice can only be of character type! |\n");
            printf("|______________________________________________|\n\n");
        }
        else if (choice == 'n' || choice == 'N'){
            printf("\n ------------\n");
            printf("| Exiting... |\n");
            printf("|____________|\n\n");
            return;
        }
        else if (choice == 'y' || choice == 'Y'){
            break;
        }
        printf("\n -------------------------------\n");
        printf("| Choice can only be 'y' or 'n' |\n");
        printf("|_______________________________|\n\n");
    }
    admin_hash_table_delete(delete_admin_id);
    admin_update_file();
}
//lookup admin
void lookup_admins(){
    char lookup_id[MAX_ID];

    printf("Enter ID of user you wish to lookup: ");
    scanf("%s", lookup_id);

    printf("\n");

    if(strlen(lookup_id) == 0){
        printf(" ----------------------------\n");
        printf("| ERROR: ID cannot be empty! |\n");
        printf("|____________________________|\n\n");
        return;
    }
    else if(strlen(lookup_id) >= MAX_ID){
        printf(" ----------------------------------------\n");
        printf("| ERROR: ID cannot exceed %d characters! |\n", MAX_ID-1);
        printf("|________________________________________|\n\n");
        return;
    }
    else if(admin_hash_table_lookup(lookup_id) == NULL){
        printf(" ---------------------------------------\n");
        printf("| ERROR: This admin ID does not exists! |\n");
        printf("|_______________________________________|\n\n");
        return;
    }

    administrator *lookup_admin = admin_hash_table_lookup(lookup_id);
    char password_empty[] = "NON VISIBLE";
    admin_personal_info(lookup_admin, password_empty);
}
//list admins
void list_admins(){
    char password[] = "NOT VISIBLE";
    printf(" -------------------------------------------------------------------------------------------\n");
    printf("|                                 Admin Personal Information                                |\n");
    printf("|===========================================================================================|\n");
    printf("|         Name         |       Surname        |          ID          |       Password       |\n");
    printf("|----------------------|----------------------|----------------------|----------------------|\n");

    for (int i = 0; i < TABLE_SIZE; i++)
    {
        if (admin_hash_table[i] != NULL && admin_hash_table[i] != &deleted_admin_entry) {
            administrator *admin = admin_hash_table[i];
            printf("| %-20s | %-20s | %-20s | %-20s |\n", admin->name, admin->surname, admin->id, password);
        }
    }
    printf("|___________________________________________________________________________________________|\n\n");
}

//welcome menu
void welcome_menu(){
    printf(" WELCOME (CTRL + C to force exit the program at any time)\n");
    printf(" ----------------------------------------\n");
    printf("|              Banking System            |\n");
    printf("|----------------------------------------|\n");
    printf("| 1. Login as user                       |\n");
    printf("| 2. Login as administrator              |\n");
    printf("| 3. Exit                                |\n");
    printf("|________________________________________|\n");;

}
//user menu
void user_menu(){
    printf(" ----------------------------------------\n");
    printf("|                User Menu               |\n");
    printf("|----------------------------------------|\n");
    printf("| 1. Check Account Balance               |\n");
    printf("| 2. Check Personal Info                 |\n");
    printf("| 3. Set Transaction                     |\n");
    printf("| 4. See Transaction History             |\n");
    printf("| 5. Exit                                |\n");
    printf("|________________________________________|\n\n");
}
//admin menu
void admin_menu(){
    printf(" ----------------------------------------\n");
    printf("|               Admin Menu               |\n");
    printf("|----------------------------------------|\n");
    printf("| 1. Insert a User                       |\n");
    printf("| 2. Delete a User                       |\n");
    printf("| 3. Lookup a User                       |\n");
    printf("| 4. List of all Users                   |\n");
    printf("| 5. Insert a Admin                      |\n");
    printf("| 6. Delete a Admin                      |\n");
    printf("| 7. Lookup a Admin                      |\n");
    printf("| 8. List of all Admins                  |\n");
    printf("| 9. Exit                                |\n");
    printf("|________________________________________|\n\n");
}

//cleaning admin and user hash
void clean_hash(){
        for (int i = 0; i < TABLE_SIZE; i++) {
        person *p = user_hash_table[i];
        administrator *a = admin_hash_table[i];
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