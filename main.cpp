#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <future>

#include "sha256.h"
#include "passwd-utils.hpp"

std::string reduce(const std::string &hash, int index, int passwdSize);

void generateTable(std::ifstream &fin_pwd, std::ofstream &fout_table);

static std::mutex mutexRound;
void attackRound(std::string head, std::string tail, bool found,
                 std::string tempHash, std::string currHash,
                 std::size_t pwdSize, std::ofstream &fout_crackedPwd);
void attack(std::ifstream &fin_hashes, std::ifstream &fin_rbtable, std::ofstream &fout_crackedPwd);

int main(int argc, char const *argv[])
{
    if (argc != 2 && argc != 3) // Checks the number or arguments
    {
        std::cerr << "Wrong number of arguments.\n";
        return -1;
    }
    else if (strcmp(argv[1], "-g") && strcmp(argv[1], "-a")) // Checks the options
    {
        std::cerr << "Wrong options.\n";
        return -1;
    }

    if (strcmp(argv[1], "-g") == 0)
    {
        std::ifstream fin_pwd{argv[2]}; // Input file
        if (fin_pwd.fail())
        {
            std::cerr << "Passwd file could not be opened\n";
            return -1;
        }
        // Generate Rainbow Table
        std::cout << "Building Rainbow table ...\n";
        std::ofstream fout_table{"rb_table.txt"};
        generateTable(fin_pwd, fout_table);
        fin_pwd.close();
        fout_table.close();
        std::cout << "Rainbow table generated.\n";
        // End generate
    }
    else if (strcmp(argv[1], "-a") == 0)
    {
        // Attack
        std::cout << "Attacking Rainbow table ...\n";
        std::ifstream fin_hashes{"hashes.txt"};
        std::ifstream fin_rbtable{"rb_table.txt"};
        if (fin_hashes.fail() || fin_rbtable.fail())
        {
            std::cerr << "Hash file or rainbow table file could not be opened\n";
            return -1;
        }
        std::ofstream fout_crackedPwd{"cracked_pwd.txt"};
        attack(fin_hashes, fin_rbtable, fout_crackedPwd);
        fin_hashes.close();
        fin_rbtable.close();
        fout_crackedPwd.close();
        std::cout << "Attack ended.\n";
        // End attack
        double success = rainbow::mass_check("cracked_pwd.txt", "hashes.txt");
        std::cout << std::setprecision(4) << success << "% success" << std::endl;
    }

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
    int current{0};
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

void attackRound(std::string head, std::string tail, bool found,
                 std::string tempHash, std::string currHash,
                 std::size_t pwdSize, std::ofstream &fout_crackedPwd)
{
    std::lock_guard<std::mutex> lock(mutexRound);
    for (int i{0}; i < 50000 && !found; i++)
    {
        tempHash = reduce(tempHash, i, pwdSize);
        if (tempHash.compare(tail) == 0)
        {
            // Finding the password
            std::string currPassword = head;
            std::string previousPassword;
            for (int j{0}; j < 50000 && !found; j++)
            {
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
        //else
        //{
        tempHash = sha256(tempHash);
        //}
    }
}

void attack(std::ifstream &fin_hashes, std::ifstream &fin_rbtable,
            std::ofstream &fout_crackedPwd)
{
    std::vector<std::future<void>> futures;
    bool found = false;
    std::string currHash;
    std::string rbLine;
    int current{0};
    while (std::getline(fin_hashes, currHash) && std::getline(fin_rbtable, rbLine))
    {
        //std::string token = line.substr(0, pos);
        std::string head{strtok(&*rbLine.begin(), ",")};
        std::string tail{strtok(NULL, ",")};
        std::size_t pwdSize = head.size();
        std::string tempHash = currHash;
        futures.push_back(std::async(std::launch::async, attackRound,
                                     head, tail, found, tempHash,
                                     currHash, pwdSize, std::ref(fout_crackedPwd)));
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
