#include <stdio.h>

int main() {
    int pin = 1234; // Predefined PIN
    int enteredPin, choice;
    float balance = 1000.0; // Initial balance

    // Prompt user to enter PIN
    printf("Enter your PIN: ");
    scanf("%d", &enteredPin);

    // Check if the entered PIN is correct
    if (enteredPin != pin) {
        printf("Incorrect PIN. Access denied.\n");
        return 1; // Exit the program
    }

    // ATM operations menu
    do {
        printf("\nATM Menu:\n");
        printf("1. Check Balance\n");
        printf("2. Deposit Money\n");
        printf("3. Withdraw Money\n");
        printf("4. Exit\n");
        printf("Choose an option: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                // Check balance
                printf("Your current balance is: $%.2f\n", balance);
                break;
            case 2:
                // Deposit money
                {
                    float deposit;
                    printf("Enter amount to deposit: ");
                    scanf("%f", &deposit);
                    if (deposit > 0) {
                        balance += deposit;
                        printf("Successfully deposited $%.2f. New balance: $%.2f\n", deposit, balance);
                    } else {
                        printf("Invalid deposit amount!\n");
                    }
                }
                break;
            case 3:
                // Withdraw money
                {
                    float withdraw;
                    printf("Enter amount to withdraw: ");
                    scanf("%f", &withdraw);
                    if (withdraw > 0 && withdraw <= balance) {
                        balance -= withdraw;
                        printf("Successfully withdrew $%.2f. New balance: $%.2f\n", withdraw, balance);
                    } else {
                        printf("Invalid withdrawal amount or insufficient balance!\n");
                    }
                }
                break;
            case 4:
                // Exit
                printf("Thank you for using the ATM. Goodbye!\n");
                break;
            default:
                printf("Invalid choice! Please select a valid option.\n");
        }
    } while (choice != 4); // Continue until the user chooses to exit

    return 0;
}
