#ifndef RAINBOW_UTILS_H
#define RAINBOW_UTILS_H

#include <iostream>
#include <future>

namespace rainbow
{
    std::string reduce(const std::string &hash, int index, int passwdSize);

    static std::mutex mutexGen;
    void generateChain(std::string currPassword, std::ofstream &fout_table);
    void generateTable(const std::string &pwd_path, const std::string &table_path);

    static std::mutex mutexAttack;
    void attackRound(std::string head, std::string tail, std::string hash,
                     std::size_t pwdSize, std::ofstream &fout_crackedPwd);
    void attack(const std::string &fin_hashes_path, const std::string &fin_rbtable_path,
                const std::string &fout_crackedPwd_path);
}

#endif