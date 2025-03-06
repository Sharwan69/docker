#include <stdio.h>

int main() {
    float units, bill;

    // Prompt the user to enter the number of units consumed
    printf("Enter the number of units consumed: ");
    scanf("%f", &units);

    // Calculate the bill based on the units consumed
    if (units < 0) {
        printf("Invalid input! Units consumed cannot be negative.\n");
        return 1; // Exit the program with an error code
    } else if (units <= 100) {
        bill = units * 1.5; // Rate for first 100 units
    } else if (units <= 300) {
        bill = (100 * 1.5) + ((units - 100) * 2.5); // Rate for next 200 units
    } else {
        bill = (100 * 1.5) + (200 * 2.5) + ((units - 300) * 3.5); // Rate for above 300 units
    }

    // Add fixed charges
    bill += 50; // Fixed charge

    // Display the total bill
    printf("Total electricity bill: %.2f\n", bill);

    return 0;
}
