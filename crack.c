#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings


void trim(char* input)
{
    int input_length = strlen(input);

    // I used a FOR with a break instead of a WHILE
    // as I just wanted that guaranteed breakout condition
    // while iterating easily.
    for(int i = 0; i < input_length; i++)
    {
        // I habitually had to try to capture '\r'
        if( input[i] == '\n' || input[i] == '\r' )
        {
            input[i] = '\0';
            break;
        }
    }
}

// Given a target plaintext word, use it to try to find
// a matching hash in the hashFile.
// Get this function working first!
char * tryWord(char * plaintext, char * hashFilename)
{
    char* hash;
    // Hash the plaintext
    hash = md5(plaintext, strlen(plaintext));
    
    // Open the hash file
    FILE* readFromHashFile = fopen(hashFilename, "r");
    if(!readFromHashFile)
    {
        printf("Hash file \"%s\" is unable to be opened for read.\n", hashFilename);
        return NULL;
    }

    char providedHash[HASH_LEN];
    int result = 0;
    // Loop through the hash file, one line at a time.
    while(!feof(readFromHashFile))
    {
        // Get a line from the file, make sure we don't double-read the last line
        if(fgets(providedHash, HASH_LEN, readFromHashFile))
        {
            trim(providedHash);

            // Attempt to match the hash from the file to the
            // hash of the plaintext.
            result = strcmp(hash, providedHash);

            // If there is a match, you'll return the hash.
            // If not, return NULL.
            //      *** we don't want to free the hash as we need that pointer!
            if(result == 0)
            {
                fclose(readFromHashFile);
                return(hash);
            }
        }
    }

    // Before returning, do any needed cleanup:
    //   Close files?
    //   Free memory?
    fclose(readFromHashFile);

    // No matches, so free hash
    free(hash);

    // Modify this line so it returns the hash
    // that was found, or NULL if not found.
    return NULL;
}


int main(int argc, char *argv[])
{
    if (argc < 3) 
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    char dictWord[PASS_LEN];
    int findcount = 0;

    // Open the dictionary file for reading.
    FILE* readFromDictFile = fopen(argv[2], "r");
    if(!readFromDictFile)
    {
        printf("Dict file \"%s\" is unable to be opened for read.\n", argv[2]);
        exit(1);
    }

    // For each dictionary word, pass it to tryWord, which
    // will attempt to match it against the hashes in the hash_file.

    while(!feof(readFromDictFile))
    {
        // Get a line from the file, make sure we don't double-read the last line
        if(fgets(dictWord, PASS_LEN, readFromDictFile))
        {
            trim(dictWord);

            char *found = tryWord(dictWord, argv[1]);

    
            // If we got a match, display the hash and the word. For example:
            //   5d41402abc4b2a76b9719d911017c592 hello
            if(found)
            {
                printf("%s %s\n", found, dictWord);
                findcount++;
                free(found);
            }
        }
    }
    
    // Close the dictionary file.
    fclose(readFromDictFile);

    // Display the number of hashes that were cracked.
    printf("%d hashes cracked!\n", findcount);
    
    // Free up any malloc'd memory?
    //   handled in-loop
}

