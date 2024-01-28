/* DUKH Attack
 * COMP10002 Foundations of Algorithms, Semester 1, 2021
 * Skeleton code written by Shaanan Cohney, April 2021
 */

/****** Include libraries ******/

#include <stdio.h>
#include <stdlib.h>
/* Do NOT use the following two libraries in stage 1! */
#include <string.h>
#include <ctype.h>

/* Provides functions AES_encrypt and AES_decrypt (see the assignment spec) */
#include "aes.h"
/* Provides functions to submit your work for each stage.
 * See the definitions in a1grader.h, they are all available to use.
 * But don't submit your stages more than once... that's weird! */
#include "a1grader.h"

#define NDEBUG 1
#include <assert.h>

/****** Definitions of constants ******/

#define BOOK_LENGTH 1284    /* The maximum length of a cipher book */
#define MAX_MSG_LENGTH 1024 /* The maximum length of an encrypted message */
#define BLOCKSIZE 16        /* The length of a block (key, output) */
#define N_TIMESTEPS 20      /* number of timesteps */
#define N_OUTPUT_BLOCKS 2   /* number of output blocks */

// TODO Add your own #defines here, if needed
const int ACCESSIBLE_TIMESTEPS[] = {9, 10};

/****** Type definitions ******/
/* Recall that these are merely aliases, or shortcuts to their underlying types.
 * For example, block_t can be used in place of an array, length 16 (BLOCKSIZE)
 * of unsigned char, and vice versa. */

typedef char book_t[BOOK_LENGTH];     /* A cipherbook (1284 bytes) */
typedef unsigned char byte_t;         /* A byte (8 bits) */
typedef byte_t block_t[BLOCKSIZE];    /* A cipher bitset (block) (16 bytes) */
typedef byte_t msg_t[MAX_MSG_LENGTH]; /* An encrypted message (l bytes) */

// TODO Add your own type definitions here, if needed

/****** Function Prototypes ******
 * There are more functions defined in aes.h and grader.h */
// Scaffold
int read_hex_line(byte_t output[], int max_count, char *last_char);
void stage0(msg_t ciphertext, int *ciphertext_length,
            block_t outputs[N_OUTPUT_BLOCKS], block_t timesteps[N_TIMESTEPS],
            book_t cipherbook);
void stage1(book_t cipherbook, int *book_len);
void stage2(byte_t codebook[], int book_len, block_t outputs[N_OUTPUT_BLOCKS],
            block_t timesteps[N_TIMESTEPS], block_t key2);
void stage3(block_t key2, block_t outputs[N_OUTPUT_BLOCKS],
            block_t timesteps[N_TIMESTEPS], byte_t key1[], int cipher_length);
void stage4(byte_t key1[], byte_t ciphertext[], int cipher_length,
            byte_t plaintext[]);

// TODO: Put your own function prototypes here! Recommended: separate into stages.

/* Stage 0 */
void cipherbook_func(book_t book);

/* Stage 1 */
void strip_punctuation(book_t cipherbook, byte_t *stripped, int *new);
void replace_text(book_t cipherbook, byte_t *stripped);

/* Stage 2 */
int get_index(int block_num);
void copy_key2(block_t original, int max_length, int original_initial_index, block_t new);
void XOR_calculator(block_t input1, block_t input2, int max_size, block_t output_xor);
void aes_lhs(block_t output, block_t key_test, block_t timestep, block_t output_lh);
void aes_rhs(block_t output, block_t key_test, block_t timestep, block_t output_rh);
int same_aes(block_t outputLH, block_t outputRH);

/* Stage 3 */
void calculate_init_val(block_t key2, block_t output, block_t timestep, block_t val);
void generate_output(block_t intermediate, block_t val, block_t key2, block_t output);
void calculate_new_val(block_t newOutput, block_t intermediate, block_t key2, block_t val);
void copy_key1(block_t output, int max_length, int key_index, block_t key1);

/* Stage 4 */
void XOR_calculator2(byte_t input1[], byte_t input2[], int max_size, byte_t output_xor[]);

/* The main function of the program */
// It is strongly suggested you do NOT modify this function.
int main(int argc, char *argv[])
{

    /* These will store our input from the input file */
    msg_t ciphertext;                 // encrypted message, to be decrypted in the attack
    int ciphertext_length = 0;        // length of the encrypted message
    book_t cipherbook;                // book used to make key k2
    block_t timesteps[N_TIMESTEPS];   // timesteps used to generate outputs (hex)
    block_t outputs[N_OUTPUT_BLOCKS]; // outputs from the random number generator (hex)

    /* Other variables */
    int stripped_length;              // length of the cipher book after having removed punctuation
    block_t key2;                     // the key k2 (hexadecimal)
    byte_t key1[MAX_MSG_LENGTH];      // the key k1 (hexadecimal)
    byte_t plaintext[MAX_MSG_LENGTH]; // the plaintext output

    /* Stage 0 */
    stage0(ciphertext, &ciphertext_length, outputs, timesteps, cipherbook);
    submit_stage0(ciphertext_length, ciphertext, outputs, timesteps, cipherbook);

    /* Stage 1 */
    stage1(cipherbook, &stripped_length);
    submit_stage1(cipherbook, stripped_length);

    /* Stage 2 */
    stage2((byte_t *)cipherbook, stripped_length, outputs, timesteps, key2);
    submit_stage2(key2);

    /* Stage 3 */
    stage3(key2, outputs, timesteps, key1, ciphertext_length);
    submit_stage3(key1);

    /* Stage 4 */
    stage4(key1, ciphertext, ciphertext_length, plaintext);
    submit_stage4(plaintext);

    return 0;
}

/********* Scaffold Functions *********/

/* Reads a line in from stdin, converting pairs of hexadecimal (0-F) chars to
 * byte_t (0-255), storing the result into the output array,
 * stopping after max_count values are read, or a newline is read.
 *
 * Returns the number of *bytes* read.
 * The last char read in from stdin is stored in the value pointed to by last_char.
 * If you don't need to know what last_char is, set that argument to NULL
 */
int read_hex_line(byte_t output[], int max_count, char *last_char)
{
    char hex[2];
    int count;
    for (count = 0; count < max_count; count++)
    {
        /* Consider the first character of the hex */
        hex[0] = getchar();
        if (hex[0] == '\n')
        {
            if (last_char)
            {
                *last_char = hex[0];
            }
            break;
        }
        /* Now the second */
        hex[1] = getchar();
        if (last_char)
        {
            *last_char = hex[0];
        }
        if (hex[1] == '\n')
        {
            break;
        }

        /* Convert this hex into an int and store it */
        output[count] = hex_to_int(hex); // (defined in aes.h)
    }

    return count;
}

/********* Stage 0 Functions *********/
/**
 * Reads in the input file from stdin and stores each line in the function arguments
 */
void stage0(msg_t ciphertext, int *ciphertext_length, block_t outputs[N_OUTPUT_BLOCKS],
            block_t timesteps[N_TIMESTEPS], book_t cipherbook)
{

    /* Input Line 1: Length of encrypted message in bytes */
    scanf("%d", &*ciphertext_length);
    scanf("\n"); // disregard newline prior to next input line

    /* Input Line 2: Ciphertext in hexadecimals bytes */
    read_hex_line(ciphertext, MAX_MSG_LENGTH, NULL);

    /* Input Line 3: Outputs O9 and O10 from the random number generator */
    read_hex_line(outputs[0], MAX_MSG_LENGTH, NULL);

    /* Input Line 4: Timesteps T0 through T19 */
    read_hex_line(timesteps[0], MAX_MSG_LENGTH, NULL);

    /* Input Line 5: Cipher book */
    cipherbook_func(cipherbook);
}

// TODO: Add functions here, if needed.
/**
 * Stores the first 1284 characters of the text into the cipher book
 */
void cipherbook_func(book_t book)
{
    int c;
    for (int i = 0; i < BOOK_LENGTH; i++)
    {
        c = getchar();
        if (c != EOF && c != '\n')
        {
            book[i] = c;
        }
    }
}

/********* Stage 1 Functions *********/
// Reminder: you *cannot* use string.h or ctype.h for this stage!

/**
 * Strips punctuation from the stored cipherbook
 */
void stage1(book_t cipherbook, int *book_len)
{
    byte_t stripped[BOOK_LENGTH];
    *book_len = 0;
    strip_punctuation(cipherbook, stripped, book_len);
    replace_text(cipherbook, stripped);
}

// TODO: Add functions here, if needed.

/**
 * Stores a cipher book stripped off its punctuations
 */
void strip_punctuation(book_t cipherbook, byte_t *stripped, int *stripped_len)
{
    for (int i = 0; i < BOOK_LENGTH; i++)
    {
        if (cipherbook[i] >= 'a' && cipherbook[i] <= 'z')
        {
            stripped[*stripped_len] = cipherbook[i];
            (*stripped_len)++;
        }
    }
}

/**
 * Replaces the text of the original cipherbook with that of the stripped cipherbook
 */
void replace_text(book_t cipherbook, byte_t *stripped)
{
    for (int i = 0; i < BOOK_LENGTH; i++)
    {
        cipherbook[i] = stripped[i];
    }
}

/********* Stage 2 Functions *********/
/**
 * Guesses the key k2
 */
void stage2(byte_t codebook[], int book_len, block_t outputs[N_OUTPUT_BLOCKS],
            block_t timesteps[N_TIMESTEPS], block_t key2)
{
    int block_num = 1;
    block_t key_test, output_lh, output_rh;

    /* Loops through all blocks */
    while (block_num <= book_len / BLOCKSIZE)
    {
        /* Makes a guess of the key 2 */
        copy_key2(codebook, BLOCKSIZE, get_index(block_num), key_test);

        /* Calculates both sides of the equation */
        aes_lhs(outputs[1], key_test, timesteps[ACCESSIBLE_TIMESTEPS[1]], output_lh);
        aes_rhs(outputs[0], key_test, timesteps[ACCESSIBLE_TIMESTEPS[0]], output_rh);

        /* The value of key_test is correct */
        if (same_aes(output_lh, output_rh))
        {
            break;
        }

        block_num++;
    }

    /* Stores the correct key2 */
    copy_key2(key_test, BLOCKSIZE, 0, key2);
}

// TODO: Add functions here, if needed.
/**
 * Determines the initial index based on the block number
 */
int get_index(int block_num)
{
    if (block_num == 1)
    {
        return 0;
    }
    else
    {
        return (block_num - 1) * BLOCKSIZE;
    }
}

/**
 * Creates a copy of a given block into key 2
 */
void copy_key2(block_t original, int max_length, int original_init_index, block_t new)
{
    for (int i = 0; i < max_length; i++)
    {
        new[i] = original[original_init_index];
        original_init_index++;
    }
}

/**
 * Calculate the XOR product
 */
void XOR_calculator(block_t input1, block_t input2, int max_size, block_t output_xor)
{
    for (int i = 0; i < max_size; i++)
    {
        output_xor[i] = input1[i] ^ input2[i];
    }
}

/**
 * Calculates the left side of the equation
 */
void aes_lhs(block_t output, block_t key_test, block_t timestep, block_t output_lhs)
{
    block_t output1, output2, output3;
    AES_decrypt(output, key_test, output1);
    AES_encrypt(timestep, key_test, output2);
    XOR_calculator(output1, output2, BLOCKSIZE, output3);
    AES_decrypt(output3, key_test, output_lhs);
}

/**
 * Calculates the right side of the equation
 */
void aes_rhs(block_t output, block_t key_test, block_t timestep, block_t output_rhs)
{
    block_t output1;
    AES_encrypt(timestep, key_test, output1);
    XOR_calculator(output, output1, BLOCKSIZE, output_rhs);
}

/**
 * Checks if both sides of the equation are equal
 */
int same_aes(block_t output_lhs, block_t output_rhs)
{
    int count = 0;
    for (int i = 0; i < BLOCKSIZE; i++)
    {
        if (output_lhs[i] == output_rhs[i])
        {
            count++;
        }
    }
    return count == BLOCKSIZE;
}

/********* Stage 3 Functions *********/
/**
 * Generates the key k1 using a pseudo random number generator
 */
void stage3(block_t key2, block_t outputs[N_OUTPUT_BLOCKS],
            block_t timesteps[N_TIMESTEPS], byte_t key1[], int ciphertext_length)
{

    int i = 1; // starting index
    block_t val, intermediate, newOutput;

    /* Calculates the initial value (V10) */
    calculate_init_val(key2, outputs[1], timesteps[ACCESSIBLE_TIMESTEPS[1]], val);

    /* Calculates each output into key1 */
    while (i <= ciphertext_length / BLOCKSIZE)
    {

        /* Calculates the intermediate value */
        AES_encrypt(timesteps[ACCESSIBLE_TIMESTEPS[1] + i], key2, intermediate);

        /* Generates 128 bits of output */
        generate_output(intermediate, val, key2, newOutput);

        /* Calculates the value for the next iteration */
        calculate_new_val(newOutput, intermediate, key2, val);

        /* Copies the output into key1 */
        copy_key1(newOutput, BLOCKSIZE, get_index(i), key1);

        i++;
    }
}

// TODO: Add functions here, if needed.
/**
 * Calculates the initial value
 */
void calculate_init_val(block_t key2, block_t output, block_t timestep, block_t val)
{
    block_t output1, output2;
    AES_encrypt(timestep, key2, output1);
    XOR_calculator(output, output1, BLOCKSIZE, output2);
    AES_encrypt(output2, key2, val);
}

/**
 * Generates the output for a value
 */
void generate_output(block_t intermediate, block_t val, block_t key2, block_t output)
{
    block_t output1;
    XOR_calculator(intermediate, val, BLOCKSIZE, output1);
    AES_encrypt(output1, key2, output);
}

/**
 * Calculates the value for a given output
 */
void calculate_new_val(block_t newOutput, block_t intermediate, block_t key2, block_t val)
{
    block_t output;
    XOR_calculator(newOutput, intermediate, BLOCKSIZE, output);
    AES_encrypt(output, key2, val);
}

/**
 * Copies the output into key1
 */
void copy_key1(block_t output, int max_length, int key_index, block_t key1)
{
    for (int k = 0; k < max_length; k++)
    {
        key1[key_index] = output[k];
        key_index++;
    }
}

/********* Stage 4 Functions *********/
/**
 * Decrypts the original message
 */
void stage4(byte_t key1[], byte_t ciphertext[], int cipher_length, byte_t plaintext[])
{
    /* Calculates and stores the plaintext */
    XOR_calculator2(key1, ciphertext, cipher_length, plaintext);
}

// TODO: Add functions here, if needed.

/**
 * Calculates the XOR product between a key and a ciphertext to produce the plaintext
 */
void XOR_calculator2(byte_t key[], byte_t ciphertext[], int max_size, byte_t plaintext[])
{
    for (int i = 0; i < max_size; i++)
    {
        plaintext[i] = key[i] ^ ciphertext[i];
    }
}
/********* END OF ASSIGNMENT! *********/