#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <future>

#include "sha256.h"
#include "passwd-utils.hpp"
#include "ThreadPool.h"

std::string reduce(const std::string &hash, int index, int passwdSize);

static std::mutex mutexGen;
void generateChain(std::string currPassword, std::ofstream &fout_table);
void generateTable(const std::string &pwd_path, const std::string &table_path);

static std::mutex mutexAttack;
void attackRound(std::string head, std::string tail,
                 std::string tempHash, std::string currHash,
                 std::size_t pwdSize, std::ofstream &fout_crackedPwd);
void attack(const std::string &fin_hashes_path, const std::string &fin_rbtable_path,
            const std::string &fout_crackedPwd_path);

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
        // Generate Rainbow Table
        std::cout << "Building Rainbow table ...\n";
        generateTable(argv[2], "rb_table.txt");
        std::cout << "Rainbow table generated.\n";
        // End generate
    }
    else if (strcmp(argv[1], "-a") == 0)
    {
        // Attack
        std::cout << "Attacking Rainbow table ...\n";
        attack("hashes.txt", "rb_table.txt", "cracked_pwd.txt");
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

void generateChain(std::string currPassword, std::ofstream &fout_table)
{
    auto pwdSize{currPassword.size()};
    std::string tail = currPassword;
    for (int i{0}; i < 50000; i++)
    {
        tail = sha256(tail);
        tail = reduce(tail, i, pwdSize);
    }
    std::lock_guard<std::mutex> lock(::mutexGen);
    fout_table << currPassword << "," << tail << '\n';
}

void generateTable(const std::string &pwd_path, const std::string &table_path)
{
    std::ifstream fin_pwd{pwd_path}; // Input file
    if (fin_pwd.fail())
    {
        std::cerr << "Passwd file could not be opened\n";
        exit(1);
    }
    std::ofstream fout_table{"rb_table.txt"};

    ThreadPool pool{std::thread::hardware_concurrency()};
    std::vector<std::future<void>> futures;

    for (std::string currPassword; std::getline(fin_pwd, currPassword);)
        futures.push_back(pool.enqueue(generateChain, currPassword, std::ref(fout_table)));

    for (const auto &f : futures)
        f.wait();

    fin_pwd.close();
    fout_table.close();
}

void attackRound(std::string head, std::string tail,
                 std::string tempHash, std::string currHash,
                 std::size_t pwdSize, std::ofstream &fout_crackedPwd)
{
    bool found = false;
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
                    std::lock_guard<std::mutex> lock(::mutexAttack);
                    fout_crackedPwd << previousPassword << '\n';
                    found = true;
                }
                currPassword = reduce(currPassword, j, pwdSize);
            }
        }
        tempHash = sha256(tempHash);
    }
}

void attack(const std::string &fin_hashes_path, const std::string &fin_rbtable_path,
            const std::string &fout_crackedPwd_path)
{
    std::ifstream fin_hashes{fin_hashes_path};
    std::ifstream fin_rbtable{fin_rbtable_path};
    if (fin_hashes.fail() || fin_rbtable.fail())
    {
        std::cerr << "Hash file or rainbow table file could not be opened\n";
        exit(1);
    }
    std::ofstream fout_crackedPwd{fout_crackedPwd_path};

    ThreadPool pool{std::thread::hardware_concurrency()};
    std::vector<std::future<void>> futures;

    std::string currHash;
    std::string rbLine;
    while (std::getline(fin_hashes, currHash))
    {
        while (std::getline(fin_rbtable, rbLine))
        {
            std::string head{strtok(&*rbLine.begin(), ",")};
            std::string tail{strtok(NULL, ",")};
            std::size_t pwdSize = head.size();
            std::string tempHash = currHash;
            futures.push_back(pool.enqueue(attackRound, head, tail, tempHash,
                                           currHash, pwdSize, std::ref(fout_crackedPwd)));
        }
        fin_rbtable.clear();
        fin_rbtable.seekg(0);
    }

    for (const auto &f : futures)
        f.wait();

    fin_hashes.close();
    fin_rbtable.close();
    fout_crackedPwd.close();
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
