#include <stdio.h>

int main() {
    int numSubjects, i;
    float score, total = 0.0, average;
    char grade;

    // Ask the user for the number of subjects
    printf("Enter the number of subjects: ");
    scanf("%d", &numSubjects);

    // Loop to get scores for each subject
    for (i = 1; i <= numSubjects; i++) {
        printf("Enter score for subject %d: ", i);
        scanf("%f", &score);
        total += score; // Accumulate the total score
    }

    // Calculate the average
    average = total / numSubjects;

    // Determine the letter grade based on the average
    if (average >= 90) {
        grade = 'A';
    } else if (average >= 80) {
        grade = 'B';
    } else if (average >= 70) {
        grade = 'C';
    } else if (average >= 60) {
        grade = 'D';
    } else {
        grade = 'F';
    }

    // Display the results
    printf("Total Score: %.2f\n", total);
    printf("Average Score: %.2f\n", average);
    printf("Grade: %c\n", grade);

    return 0;
}
