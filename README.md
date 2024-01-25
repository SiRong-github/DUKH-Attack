# University Subject
This is a project for COMP10002 Foundations of Algorithms of the University of Melbourne.

# About the Project
## File Purpose
The program decrypts an encrypted message while knowing some details on its generation.

## File-Level Documentation

The program reads in 5 lines of input:
1. l: Length of encrypted message in bytes with a max value of 1024
2. Encrypted Message encrypted with a one time pad under key k1, which has a length of l characters
3. O9 and O10: Outputs from the random number generator, in groups of 16 characters, where each is represented as a two-digit hexadecimal number in the file
4. T0 through T19: Timesteps used to generate O0 to O19, in groups of 16-characters (blocks), where each character is represented as a two-digit hexadecimal number in the file
5. The first 1284 characters in the cipher book, a novel

Afterwards, it reads in the text of the cipher book and finds which 16-character block has been used as the key k2 for the random number generator.
Then, it generates enough output from the generator to produce k1 and use it to decrypt the original message.

# Provided Template Code, Source Files (and Their Libraries)  and Test Cases

1. Template Code
    scaffold.c
        a. Stage 0: Reading Input File
        b. Stage 1: Stripping Punctuation
        c. Stage 2: Guessing the key k2
        d. Stage 3: Generating the key k1
        e. Stage 4: Decrypting the original message

2. Source Files and Their Libraries
    a. aes.c & aes.h: simple AES implementation functions
    b. a1grader.c & a1grader.h: testing each stage of the assignment

3. Test Cases
    a. assignment1-input1.txt
    b. assignment1-input2.txt
    c. grok-input1.txt, grok-output1.txt
    d. grok-input2.txt, grok-output2.txt

# Testing

## Compiling
clang -Wall -std=c11 -pedantic program1.c aes.c a1grader.c -o program1

## Testing
./program1 < assignment1-input.txt
./program1 n < assignment1-input.txt /* for stage n */

## Comparison with sample output
bash compare.sh n program1_output.txt correctoutputfile

