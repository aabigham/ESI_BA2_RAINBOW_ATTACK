#include <iostream>
#include <fstream>
#include <vector>
#include <cmath>
#include <cstring>
#include <iomanip>

#include "sha256.h"
#include "passwd-utils.hpp"

std::string reduce(const std::string &hash, int index, int passwdSize = 8);
void generateTable(std::ifstream &fin_pwd, std::ofstream &fout_table);
void attack(std::ifstream &fin_hashes, std::ifstream &fin_rbtable, std::ofstream &fout_crackedPwd);

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
    std::ofstream fout_table{"rb_table.txt"};
    generateTable(fin_pwd, fout_table);
    fin_pwd.close();
    fout_table.close();
    // End generate

    // Attack
    std::ifstream fin_hashes{"hashes.txt"};
    std::ifstream fin_rbtable{"rb_table.txt"};
    if (fin_hashes.fail() || fin_rbtable.fail())
    {
        std::cerr << "Hash or rb table file could not be opened\n";
        return -1;
    }
    std::ofstream fout_crackedPwd{"cracked_pwd.txt"};
    attack(fin_hashes, fin_rbtable, fout_crackedPwd);
    fin_hashes.close();
    fin_rbtable.close();
    fout_crackedPwd.close();
    // End attack

    double success = rainbow::mass_check("cracked_pwd.txt", "hashes.txt");
    std::cout << std::setprecision(4) << success << "% success" << std::endl;

    return 0;
}

std::string reduce(const std::string &hash, int index, int passwdSize)
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

void generateTable(std::ifstream &fin_pwd, std::ofstream &fout_table)
{
    for (std::string currPassword; std::getline(fin_pwd, currPassword);)
    {
        auto pwdSize{currPassword.size()};
        std::string tail = currPassword;
        fout_table << currPassword << ',';
        for (int i{0}; i < 50000; i++)
        {
            tail = sha256(tail);
            tail = reduce(tail, i, pwdSize);
        }
        fout_table << tail << '\n';
    }
}

void attack(std::ifstream &fin_hashes, std::ifstream &fin_rbtable, std::ofstream &fout_crackedPwd)
{
    bool found = false;
    std::string currHash;
    std::string rbLine;
    while (std::getline(fin_hashes, currHash) && std::getline(fin_rbtable, rbLine))
    {
        //std::string token = line.substr(0, pos);
        std::string head{strtok(&*rbLine.begin(), ",")};
        std::string tail{strtok(NULL, ",")};
        auto pwdSize = head.size();
        std::string tempHash = currHash;
        for (int i{0}; i < 50000 && !found; i++)
        {
            tempHash = reduce(tempHash, i, pwdSize);

            //std::cout << "1 Step " << i << " : " << tempHash << ", " << tail << std::endl;

            //probleme de reduction
            //probleme nb  de mdp
            if (tempHash.compare(tail) == 0)
            {
                //finding the password
                std::string currPassword = head;
                std::string previousPassword;
                for (int j{0}; j < 50000 && !found; j++)
                {
                    //     std::cout << "2 Step " << j << std::endl;
                    previousPassword = currPassword;
                    currPassword = sha256(currPassword);
                    if (currPassword.compare(currHash) == 0)
                    {
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
