#include "bankingsyst_head.h"

int main() {
    init_hash_table();
    atexit(clean_hash);
    char id[MAX_ID];
    char password[MAX_PASSWORD_LENGTH];
    int welcome_choice = 0;
    int choice = 0;

    welcome_menu();
    printf("Enter your choice: ");
    if (scanf("%d", &welcome_choice) != 1){
        printf(" ------------------------------------");
        printf("| ERROR: Choice can only be numeric! |\n");
        printf("|____________________________________|");
        return 1;
    }

    printf("\n");

    switch (welcome_choice)
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
            person *current_user = user_hash_table_lookup(id);
            while (1)
            {
                user_menu();

                printf("\nEnter your choice: ");
                scanf("%d", &choice);
                printf("\n\n");

                switch(choice)
                {
                    case 1:
                        check_user_balance(current_user);
                        break;
                    case 2:
                        user_personal_info(current_user, password);
                        break;
                    case 3:
                        setting_transactions(current_user);
                        break;
                    case 4:
                        read_transaction_file(current_user->id);
                        break;
                    case 5:
                        printf(" --------------------------------\n");
                        printf("| Goodbye %-20s :)|\n", current_user->name);
                        printf("|________________________________|\n");
                        return 0;
                    default:
                        printf(" ---------------------------------\n");
                        printf("| Out of range, please try again. |\n");
                        printf("|_________________________________|\n");
                        break;
                }
            }
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

            administrator *current_admin = admin_hash_table_lookup(id);
            while (1)
            {
                admin_menu();

                printf("Enter your choice: ");
                scanf("%d", &choice);
                printf("\n\n");

                switch(choice)
                {
                    case 1:
                        user_write_file();
                        break;
                    case 2:
                        delete_user();
                        break;
                    case 3:
                        lookup_users();
                        break;
                    case 4:
                        list_users();
                        break;
                    case 5:
                        admin_write_file();
                        break;
                    case 6:
                        delete_admin();
                        break;
                    case 7:
                        lookup_admins();
                        break;
                    case 8:
                        list_admins();
                        break;
                    case 9:
                        printf(" --------------------------------\n");
                        printf("| Goodbye %-20s :)|\n", current_admin->name);
                        printf("|________________________________|\n");
                        return 0;
                    default:
                        printf(" ---------------------------------\n");
                        printf("| Out of range, please try again. |\n");
                        printf("|_________________________________|\n");
                        break;
                }
            }
            break;
            
        case 3: 
            printf(" ------------\n");
            printf("| Exiting... |\n");
            printf("|____________|\n");
            return 0;

        default: 
            printf(" ---------------------------------\n");
            printf("|           Out of Range          |\n");
            printf("|_________________________________|\n");
    }
    return 0;
}
