#include <stdio.h>
#include <stdlib.h>

typedef struct {
    char name[50];
    int accountNumber;
    float balance;
} Account;

void createAccount(Account *account) {
    printf("Enter your name: ");
    scanf("%s", account->name);
    printf("Enter your account number: ");
    scanf("%d", &account->accountNumber);
    account->balance = 0.0; // Initial balance is 0
    printf("Account created successfully!\n");
}

void deposit(Account *account) {
    float amount;
    printf("Enter amount to deposit: ");
    scanf("%f", &amount);
    if (amount > 0) {
        account->balance += amount;
        printf("Successfully deposited %.2f. New balance: %.2f\n", amount, account->balance);
    } else {
        printf("Invalid deposit amount!\n");
    }
}

void withdraw(Account *account) {
    float amount;
    printf("Enter amount to withdraw: ");
    scanf("%f", &amount);
    if (amount > 0 && amount <= account->balance) {
        account->balance -= amount;
        printf("Successfully withdrew %.2f. New balance: %.2f\n", amount, account->balance);
    } else {
        printf("Invalid withdrawal amount or insufficient balance!\n");
    }
}

void checkBalance(Account *account) {
    printf("Account Holder: %s\n", account->name);
    printf("Account Number: %d\n", account->accountNumber);
    printf("Current Balance: %.2f\n", account->balance);
}

int main() {
    Account account;
    int choice;

    while (1) {
        printf("\nSimple Banking System\n");
        printf("1. Create Account\n");
        printf("2. Deposit Money\n");
        printf("3. Withdraw Money\n");
        printf("4. Check Balance\n");
        printf("5. Exit\n");
        printf("Choose an option: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                createAccount(&account);
                break;
            case 2:
                deposit(&account);
                break;
            case 3:
                withdraw(&account);
                break;
            case 4:
                checkBalance(&account);
                break;
            case 5:
                printf("Exiting the system. Goodbye!\n");
                exit(0);
            default:
                printf("Invalid choice! Please select a valid option.\n");
        }
    }

    return 0;
}
