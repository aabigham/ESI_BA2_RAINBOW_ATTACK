#include <iostream>
#include <fstream>
#include <vector>

#include "sha256.h"

std::string reduce(std::string hash, unsigned index, unsigned passwdSize);

int main(int argc, char const *argv[])
{
    std::ifstream fin{argv[1]};
    if (fin.fail())
    {
        std::cerr << "File could not be opened\n";
        return -1;
    }
    std::vector<std::pair<std::string, std::string>> data{};
    std::string currPassword;

    while (std::getline(fin, currPassword))
    {
        std::string tail;
        for (size_t i = 0; i < 50000; i++)
        {
        }
    }
    return 0;
}

std::string reduce(std::string hash, unsigned index, unsigned passwdSize)
{
    std::string reducedPwd;
    const char *chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                        "abcdefghijklmnopqrstuvwxyz"
                        "0123456789";

    for (unsigned i = 0; i < passwdSize; i++)
    {
        /* code */
    }

    int number = (int)strtol(hash.c_str(), NULL, 16);
    reducedPwd.push_back(chars[(number + index) % passwdSize]);
    return;
}