#ifndef RAINBOW_UTILS_H
#define RAINBOW_UTILS_H

#include <iostream>
#include <future>

namespace rainbow
{
    static constexpr int CHAIN_SIZE{2000};

    /**
     * Reduction function .
     */
    std::string reduce(const std::string &hash, int index, int passwdSize);

    /**
     * Mutex used in the table generation, avoiding 2 writes of threads 
     * at the same time in the output file of the rainbow table.
     */
    static std::mutex mutexGen;

    /**
     * Generates a chain of the rainbow table, allowing to retriece the head and tail. 
     */
    void generateChain(std::string currPassword, std::ofstream &fout_table);

    /**
     * Generates the entire rainbow table.
     */
    void generateTable(const std::string &pwd_path, const std::string &table_path);

    /**
     *  Mutex used in the attack, avoiding 2 writes of threads 
     *  at the same time in the output file of cracked passwords.
     */
    static std::mutex mutexAttack;

    /**
     * Runs one attack from the hash in parameter.
     */
    void attackRound(std::string head, std::string tail, std::string hash,
                     std::size_t pwdSize, std::ofstream &fout_crackedPwd);

    /**
     * Runs the rainbow attack.
     */
    void attack(const std::string &fin_hashes_path, const std::string &fin_rbtable_path,
                const std::string &fout_crackedPwd_path);
}

#endif