#include <stdio.h>

// Function to calculate factorial
unsigned long long factorial(int n) {
    if (n < 0) {
        return 0; // Factorial is not defined for negative numbers
    }
    if (n == 0 || n == 1) {
        return 1; // Base case
    }
    return n * factorial(n - 1); // Recursive case
}

// Function to generate Fibonacci sequence up to n terms
void fibonacci(int n) {
    int t1 = 0, t2 = 1, nextTerm;

    printf("Fibonacci Series: ");
    for (int i = 1; i <= n; ++i) {
        printf("%d ", t1);
        nextTerm = t1 + t2;
        t1 = t2;
        t2 = nextTerm;
    }
    printf("\n");
}

int main() {
    int choice, number;

    printf("Factorial and Fibonacci Calculator\n");
    printf("1. Calculate Factorial\n");
    printf("2. Generate Fibonacci Series\n");
    printf("Choose an option (1 or 2): ");
    scanf("%d", &choice);

    switch (choice) {
        case 1:
            printf("Enter a non-negative integer: ");
            scanf("%d", &number);
            unsigned long long result = factorial(number);
            if (result == 0) {
                printf("Factorial is not defined for negative numbers.\n");
            } else {
                printf("Factorial of %d is %llu\n", number, result);
            }
            break;
        case 2:
            printf("Enter the number of terms in the Fibonacci series: ");
            scanf("%d", &number);
            if (number < 0) {
                printf("Number of terms cannot be negative.\n");
            } else {
                fibonacci(number);
            }
            break;
        default:
            printf("Invalid choice! Please select 1 or 2.\n");
    }

    return 0;
}
