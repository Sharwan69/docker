#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    int number, guess, attempts = 0;
    const int MAX_NUMBER = 100;

    // Seed the random number generator
    srand(time(0));
    number = rand() % MAX_NUMBER + 1; // Random number between 1 and MAX_NUMBER

    printf("Welcome to the Number Guessing Game!\n");
    printf("I have selected a number between 1 and %d. Can you guess it?\n", MAX_NUMBER);

    // Loop until the user guesses the correct number
    do {
        printf("Enter your guess: ");
        scanf("%d", &guess);
        attempts++;

        if (guess > number) {
            printf("Too high! Try again.\n");
        } else if (guess < number) {
            printf("Too low! Try again.\n");
        } else {
            printf("Congratulations! You've guessed the number %d in %d attempts.\n", number, attempts);
        }
    } while (guess != number);

    return 0;
}
