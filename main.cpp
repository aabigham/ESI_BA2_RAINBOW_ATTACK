#include <iostream>
#include <cstring>
#include <iomanip>

#include "passwd-utils.hpp"
#include "RainbowUtils.h"

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
        rainbow::generateTable(pwd_path, rb_table_path);
        std::cout << "Rainbow table generated.\n";
    }
    else if (strcmp(argv[1], "-a") == 0)
    {
        std::cout << "Attacking Rainbow table \"" << rb_table_path << "\" using hashes file \"" << argv[2] << "\"...\n";
        rainbow::attack(argv[2], rb_table_path, "cracked_pwd.txt");
        std::cout << "Attack ended.\n";
        double success = rainbow::mass_check("cracked_pwd.txt", argv[2]);
        std::cout << std::setprecision(4) << success << "% success" << std::endl;
    }

    return 0;
}