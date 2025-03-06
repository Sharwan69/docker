#include <stdio.h>

int main() {
    int rows = 4; // Number of rows in the pattern
    int currentNumber = 1; // Starting number

    for (int i = 1; i <= rows; i++) { // Loop for each row
        for (int j = 1; j <= i; j++) { // Loop for each number in the row
            printf("%d ", currentNumber); // Print the current number
            currentNumber++; // Increment the number for the next position
        }
        // After each row, update the current number to the last number of the row
        currentNumber = currentNumber - 1 + i; // Set currentNumber to the last number of the current row + 1
        printf("\n"); // Move to the next line after each row
    }

    return 0;
}
