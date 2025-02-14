# Banking System in C

A secure and user-friendly banking system implemented in C. This system allows users and administrators to perform various banking operations, such as checking account balances, setting transactions, and managing user/admin accounts. The system uses hash tables for efficient data storage and OpenSSL libraries for secure password hashing and salting.

---

## Features

### User Features
- **Login as User**: Users can log in to access their accounts.
- **Check Account Balance**: View the current balance of the account.
- **Check Personal Info**: View personal information (name, surname, ID, etc.).
- **Set Transaction**: Send money to another user.
- **See Transaction History**: View a history of all transactions.
- **Exit**: Log out of the system.

### Admin Features
- **Login as Administrator**: Admins can log in to manage the system.
- **Insert a User**: Add a new user to the system.
- **Delete a User**: Remove a user from the system.
- **Lookup a User**: Search for a specific user's details.
- **List of all Users**: Display all users in the system.
- **Insert an Admin**: Add a new admin to the system.
- **Delete an Admin**: Remove an admin from the system.
- **Lookup an Admin**: Search for a specific admin's details.
- **List of all Admins**: Display all admins in the system.
- **Exit**: Log out of the system.

---

## Technical Details

### Data Structures
- **Hash Tables**: Used to store user and admin data for efficient lookup, insertion, and deletion.
  - User Hash Table: Stores `person` structures.
  - Admin Hash Table: Stores `administrator` structures.

### Security
- **Password Hashing**: Passwords are hashed and salted using OpenSSL's SHA-256 and random salt generation.
- **Secure Storage**: Hashed passwords and salts are stored in CSV files (`bankuser.csv` and `bankadmin.csv`).

### Error Handling
- The system gracefully handles incorrect inputs and other errors, providing clear error messages to the user.

---

## How It Works

### Login Screen
When the program starts, the user is greeted with a login screen:

WELCOME (CTRL + C to force exit the program at any time)
 ----------------------------------------
|              Banking System            |
|----------------------------------------|
| 1. Login as user                       |
| 2. Login as administrator              |
| 3. Exit                                |
|________________________________________|

---

### User Menu
If the user selects **1. Login as user**, they are presented with the following menu:

 ----------------------------------------
|                User Menu               |
|----------------------------------------|
| 1. Check Account Balance               |
| 2. Check Personal Info                 |
| 3. Set Transaction                     |
| 4. See Transaction History             |
| 5. Exit                                |
|________________________________________|

---

### Admin Menu
If the user selects **2. Login as administrator**, they are presented with the following menu:

 ----------------------------------------
|               Admin Menu               |
|----------------------------------------|
| 1. Insert a User                       |
| 2. Delete a User                       |
| 3. Lookup a User                       |
| 4. List of all Users                   |
| 5. Insert a Admin                      |
| 6. Delete a Admin                      |
| 7. Lookup a Admin                      |
| 8. List of all Admins                  |
| 9. Exit                                |
|________________________________________|

---

### Exit
If the user selects **3. Exit**, a goodbye message is displayed with their name.

---

## Installation and Usage

### Prerequisites
- **GCC**: To compile the C code.
- **OpenSSL**: For password hashing and salting.

---

### Compilation
To compile the program, run the following command:

```bash
gcc -o bank bankingsyst_main.c bankingsyst_operations.c -I$(brew --prefix openssl)/include -L$(brew --prefix openssl)/lib -lssl -lcrypto
```
---

### Running the Program
After compilation, run the program using:

```bash
./bank
```
---

## File Structure

- `main.c`: Contains the main program logic and menu handling.
- `banking_system.h`: Header file with structure definitions, function declarations, and constants.
- `banking_system.c`: Contains the implementation of all functions (e.g., hash table operations, file I/O, password hashing).
- `bankuser.csv`: Stores user data (name, surname, ID, hashed password, salt, balance).
- `bankadmin.csv`: Stores admin data (name, surname, ID, hashed password, salt).
- `transactions/`: Directory containing transaction history files for each user (e.g., `user123.csv`).

---

## Error Handling

The system includes robust error handling to ensure smooth operation:

- Invalid inputs (e.g., non-numeric values, empty fields).
- Duplicate IDs during user/admin insertion.
- File I/O errors (e.g., missing or corrupted CSV files).
- Maximum login attempts (10 attempts before locking out).

---

## Security Considerations

- **Password Hashing**: Passwords are never stored in plaintext. They are hashed with a unique salt for each user/admin.
- **File Permissions**: Ensure that CSV files containing sensitive data have restricted permissions.
- **Input Validation**: All user inputs are validated to prevent buffer overflows or other vulnerabilities.

---

## Acknowledgments

- **OpenSSL**: For providing the libraries used for password hashing and salting.
- **GCC**: For the C compiler used to build this project.
