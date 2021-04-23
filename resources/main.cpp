#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>
#include <cstring>

#include "sha256.h"

std::string reduce(const std::string &hash, int index, int passwdSize = 8);
void generateTable(std::ifstream &fin, std::ofstream &fout);

int main(int argc, char const *argv[])
{
    std::ifstream fin_pwd{argv[1]}; // Input file
    if (fin_pwd.fail())
    {
        std::cerr << "Passwd file could not be opened\n";
        return -1;
    }
    //From a table of passwords stored as pairs "(login,hash)" with the help of some cryptographic
    //function H, you must implement a rainbow attack.
    //— passwords are stored after a single pass through the hash function,

    // Generate Rainbow Table
    std::ofstream fout{"rb_table.txt"};
    for (std::string currPassword; std::getline(fin_pwd, currPassword);)
    {
        auto pwdSize{currPassword.size()};
        std::string tail = currPassword;
        fout << currPassword << ',';
        for (int i{0}; i < 50000; i++)
        {
            tail = sha256(tail);
            tail = reduce(tail, i, pwdSize);
        }
        fout << tail << '\n';
    }
    fin_pwd.close();
    fout.close();

    // End generate

    // Read hashes
    std::ifstream fin_hashes{"hashes.txt"};
    std::ifstream fin_rbtable{"rb_table.txt"};
    std::ofstream fout_crackedPwd{"cracked_pwd.txt"};
    if (fin_hashes.fail() || fin_rbtable.fail())
    {
        std::cerr << "Hash or rb table file could not be opened\n";
        return -1;
    }
    bool found = false;
    std::string currHash;
    std::string rbLine;
    {
        //std::string token = line.substr(0, pos);
        std::string head{strtok(&*rbLine.begin(), ",")};
        std::string tail{strtok(NULL, ",")};
        auto pwdSize = head.size();
        std::string tempHash = currHash;
        for (int i{0}; i < 50000 && !found; i++)
        {
            tempHash = reduce(tempHash, i, pwdSize);
            //std::cout << head << "," << tail << std::endl;

            // std::cout << tempHash << " vs " << tail << std::endl;
            //probleme de reduction
            //probleme nb  de mdp
            if (tempHash.compare(tail) == 0)
            {
                std::cout << "MATCH PWD" << std::endl;

                //finding the password
                std::string currPassword = head;
                std::string previousPassword;
                for (int j{0}; j < 50000 && !found; j++)
                {
                    previousPassword = currPassword;
                    currPassword = sha256(currPassword);
                    if (currPassword.compare(currHash) == 0)
                    {
                        std::cout << "MATCH HASH" << std::endl;

                        fout_crackedPwd << previousPassword << '\n';
                        found = true;
                    }
                    currPassword = reduce(currPassword, j, pwdSize);
                }
            }
            tempHash = sha256(tempHash);
        }
        found = false;
    }

    // TODO
    fin_hashes.close();
    fin_rbtable.close();
    fout_crackedPwd.close();
    return 0;
}

static std::string reduce(const std::string &hash, int index, int passwdSize)
{
    static const char chars[]{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"};
    //
    unsigned char bytes[16];
    int temp;
    for (int i = 0; i < 16; ++i)
    {
        std::sscanf(hash.c_str() + 2 * i, "%2x", &temp);
        bytes[i] = temp;
    }
    //
    std::string reduced;
    int current;
    for (int j = 0; j < passwdSize; ++j)
    {
        current = bytes[(j + index) % 16];
        reduced += chars[current % 62];
    }
    return reduced;
}

/*int charToHexa(const char &c)
{
    
    switch (c)
    {
    case 'a':
        return 10;
    case 'b':
        return 11;
    case 'c':
        return 12;
    case 'd':
        return 13;
    case 'e':
        return 14;
    case 'f':
        return 15;

    default:
        exit(1);
    }
}*/

/*static std::string reduce(std::string hash, int index, int passwdSize)
{
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::string reducedPwd;

    int n;
    for (int i{0}; i < passwdSize; i++)
    {
        const char *curr{&hash.at(i)};
        if (isdigit(*curr))
            n = (((int)strtol(curr, NULL, 10) + index) % (int)std::pow(62, passwdSize));
        else
            n = ((charToHexa(*curr) + index) % (int)std::pow(62, passwdSize));

        reducedPwd += chars[n % 62];
    }
    return reducedPwd;
}*/
