#include <stdio.h>

#define MAX_QUESTIONS 5

typedef struct {
    char question[256];
    char options[4][100];
    char answer;
} QuizQuestion;

void displayQuestion(QuizQuestion q) {
    printf("%s\n", q.question);
    for (int i = 0; i < 4; i++) {
        printf("%c. %s\n", 'A' + i, q.options[i]);
    }
}

int main() {
    QuizQuestion quiz[MAX_QUESTIONS] = {
        {
            "What is the capital of France?",
            {"Berlin", "Madrid", "Paris", "Lisbon"},
            'C'
        },
        {
            "Which planet is known as the Red Planet?",
            {"Earth", "Mars", "Jupiter", "Saturn"},
            'B'
        },
        {
            "What is the largest ocean on Earth?",
            {"Atlantic Ocean", "Indian Ocean", "Arctic Ocean", "Pacific Ocean"},
            'D'
        },
        {
            "Who wrote 'Romeo and Juliet'?",
            {"Mark Twain", "Charles Dickens", "William Shakespeare", "Jane Austen"},
            'C'
        },
        {
            "What is the chemical symbol for water?",
            {"H2O", "O2", "CO2", "NaCl"},
            'A'
        }
    };

    char userAnswer;
    int score = 0;

    printf("Welcome to the Simple Quiz Game!\n\n");

    for (int i = 0; i < MAX_QUESTIONS; i++) {
        displayQuestion(quiz[i]);
        printf("Your answer (A/B/C/D): ");
        scanf(" %c", &userAnswer); // Space before %c to consume any whitespace

        if (userAnswer == quiz[i].answer) {
            printf("Correct!\n\n");
            score++;
        } else {
            printf("Wrong! The correct answer was %c. %s\n\n", quiz[i].answer, quiz[i].options[quiz[i].answer - 'A']);
        }
    }

    printf("Your total score: %d out of %d\n", score, MAX_QUESTIONS);
    return 0;
}
