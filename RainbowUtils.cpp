#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <future>

#include "RainbowUtils.h"
#include "ThreadPool.h"
#include "sha256.h"

namespace rainbow
{
    std::string reduce(const std::string &hash, int index, int passwdSize)
    {
        static constexpr char chars[]{
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"};
        //converting string to byte
        unsigned char bytes[16];
        int temp;
        for (int i{0}; i < 16; ++i)
        {
            std::sscanf(hash.c_str() + 2 * i, "%2x", &temp);
            bytes[i] = temp;
        }

        std::string reduced;
        int current;
        for (int j{0}; j < passwdSize; ++j)
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

        for (int i{rainbow::CHAIN_SIZE + 1}; i--;)
            tail = reduce(sha256(tail), i, pwdSize);

        std::lock_guard<std::mutex> lock(rainbow::mutexGen);
        fout_table << currPassword << "," << tail << '\n';
    }

    void generateTable(const std::string &pwd_path, const std::string &table_path)
    {
        std::ifstream fin_pwd{pwd_path}; // Input file
        if (fin_pwd.fail())
        {
            std::cerr << "Password file could not be opened\n";
            exit(1);
        }
        std::ofstream fout_table{"rb_table.txt"};

        ThreadPool pool{std::thread::hardware_concurrency()};
        std::vector<std::future<void>> futures;

        for (std::string currPassword; std::getline(fin_pwd, currPassword);)
            futures.push_back(pool.enqueue(generateChain, currPassword, std::ref(fout_table)));

        for (const auto &f : futures) // Waiting for the tasks
            f.wait();

        fin_pwd.close();
        fout_table.close();
    }

    void attackRound(std::string head, std::string tail, std::string hash,
                     std::size_t pwdSize, std::ofstream &fout_crackedPwd)
    {
        std::string tempHash = hash;
        bool found = false;
        for (int i{rainbow::CHAIN_SIZE + 1}; i-- && !found;)
        { //reducing the hash to try obtain a matching password
            tempHash = reduce(tempHash, i, pwdSize);
            if (tempHash.compare(tail) == 0)
            {
                // Match with the reduced password and tail, so the hash does exist in the chain.
                std::string currPassword = head;
                std::string previousPassword;

                for (int j{rainbow::CHAIN_SIZE + 1}; j-- && !found;)
                {
                    // Looking for the password matching that hash.
                    previousPassword = currPassword;
                    currPassword = sha256(currPassword);
                    // Matching hash found
                    if (currPassword.compare(hash) == 0)
                    {
                        // Locking before writing
                        std::lock_guard<std::mutex> lock(rainbow::mutexAttack);
                        fout_crackedPwd << previousPassword << '\n';
                        std::cout << "found" << std::endl;
                        found = true;
                    }
                    /* Still reducing if not found, to go through the chain
                        to find the password we are looking for. */
                    currPassword = reduce(currPassword, j, pwdSize);
                }
            }
            /* Still reducing the hash to go through the chain,
                to find a reduction matching the tail. */
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
        std::ofstream fout_crackedPwd{fout_crackedPwd_path}; // Found passwords

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

            // We wait for the previous tasks
            for (const auto &f : futures)
                f.wait();
            futures.clear(); // Clears vector or can take too much memory

            fin_rbtable.clear(); // Resetting file head
            fin_rbtable.seekg(0);
        }

        fin_hashes.close();
        fin_rbtable.close();
        fout_crackedPwd.close();
    }
}