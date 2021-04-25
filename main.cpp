#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <future>
#include <string>

#include "sha256.h"
#include "passwd-utils.hpp"
#include "ThreadPool.h"

static constexpr char chars[]{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"};
std::string reduce(const std::string &hash, int index, int passwdSize);

static std::mutex mutexGen;
void generateChain(std::string currPassword, std::ofstream &fout_table);
void generateTable(const std::string &pwd_path, const std::string &table_path);

static std::mutex mutexAttack;
void attackRound(std::string head, std::string tail, std::string hash,
                 std::size_t pwdSize, std::ofstream &fout_crackedPwd);
void attack(const std::string &fin_hashes_path, const std::string &fin_rbtable_path,
            const std::string &fout_crackedPwd_path);

int main(int argc, char const *argv[])
{
    if (argc != 3)
    {
        std::cerr << "Wrong number of arguments.\n";
        return -1;
    }
    else if (strcmp(argv[1], "-g") && strcmp(argv[1], "-a"))
    {
        std::cerr << "Wrong options.\n";
        return -1;
    }

    const std::string rb_table_path{"rb_table.txt"};
    if (strcmp(argv[1], "-g") == 0)
    {
        const std::string pwd_path{"pwd.txt"};
        const std::string hashes_path{"hashes.txt"};
        std::cout << "Generating the passwords and hashes for the table of size " << argv[2] << " ...\n";
        rainbow::mass_generate(std::atoi(argv[2]), 6, 8, "pwd.txt", "hashes.txt");
        std::cout << "\"" << pwd_path << " and \"" << hashes_path << "\" generated.\n\n";

        std::cout << "Building Rainbow table \"" << rb_table_path << "\" ...\n";
        generateTable(pwd_path, rb_table_path);
        std::cout << "Rainbow table generated.\n";
    }
    else if (strcmp(argv[1], "-a") == 0)
    {
        std::cout << "Attacking Rainbow table \"" << rb_table_path << "\" using hashes file \"" << argv[2] << "\"...\n";
        attack(argv[2], rb_table_path, "cracked_pwd.txt");
        std::cout << "Attack ended.\n";
        double success = rainbow::mass_check("cracked_pwd.txt", argv[2]);
        std::cout << std::setprecision(4) << success << "% success" << std::endl;
    }

    return 0;
}

std::string reduce(const std::string &hash, int index, int passwdSize)
{
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
        reduced += ::chars[current % 62];
    }
    return reduced;
}

void generateChain(std::string currPassword, std::ofstream &fout_table)
{
    auto pwdSize{currPassword.size()};
    std::string tail = currPassword;

    for (int i{0}; i < 2000; i++)
        tail = reduce(sha256(tail), i, pwdSize);

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

    int i = 0;
    for (std::string currPassword; std::getline(fin_pwd, currPassword); ++i)
        futures.push_back(pool.enqueue(generateChain, currPassword, std::ref(fout_table)));

    for (const auto &f : futures)
        f.wait();

    fin_pwd.close();
    fout_table.close();
}

void attackRound(std::string head, std::string tail, std::string hash,
                 std::size_t pwdSize, std::ofstream &fout_crackedPwd)
{
    std::string tempHash = hash;
    bool found = false;
    for (int i{0}; i < 2000 && !found; ++i)
    {
        tempHash = reduce(tempHash, i, pwdSize);
        if (tempHash.compare(tail) == 0)
        {
            // Finding the password
            std::string currPassword = head;
            std::string previousPassword;

            for (int j{0}; j < 2000 && !found; ++j)
            {
                previousPassword = currPassword;
                currPassword = sha256(currPassword);
                if (currPassword.compare(hash) == 0)
                {
                    std::lock_guard<std::mutex> lock(::mutexAttack);
                    std::cout << "found\n";

                    fout_crackedPwd << previousPassword << '\n';
                    found = true;
                }
                currPassword = reduce(currPassword, j, pwdSize);
            }
        }
        tempHash = sha256(tempHash);
        std::cout << i << std::endl;
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
    std::string currHead;
    std::string currTail;
    while (std::getline(fin_hashes, currHash))
    {
        while (std::getline(fin_rbtable, rbLine))
        {
            currHead = strtok(&*rbLine.begin(), ",");
            currTail = strtok(NULL, ",");
            std::size_t pwdSize = currHead.size();
            futures.push_back(pool.enqueue(attackRound, currHead, currTail, currHash,
                                           pwdSize, std::ref(fout_crackedPwd)));
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