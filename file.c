#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *file;
    char line[256]; // Buffer to hold each line

    // Open the file in read mode
    file = fopen("example.txt", "r");
    if (file == NULL) {
        printf("Error opening file!\n");
        return 1; // Exit with error code
    }

    // Read and print each line from the file
    while (fgets(line, sizeof(line), file)) {
        printf("%s", line);
    }

    // Close the file
    fclose(file);
    return 0;
}
