#include <iostream>
#include <fstream>
#include <vector>

#include "sha256.h"

std::string reduce(std::string hash, uint index, uint passwdSize);

int main(int argc, char const *argv[])
{
    std::ifstream fin{argv[1]}; // Input file
    if (fin.fail())
    {
        std::cerr << "File could not be opened\n";
        return -1;
    }
    //From a table of passwords stored as pairs "(login,hash)" with the help of some cryptographic
    //function H, you must implement a rainbow attack.
    //— passwords are stored after a single pass through the hash function,

    std::ofstream fout{"rb_table.txt"}; // Rainbow Table
    for (std::string currPassword; std::getline(fin, currPassword);)
    {
        std::string tail = currPassword;
        fout << currPassword << ',';
        for (size_t i{0}; i < 50000; i++)
        {
            tail = sha256(tail);
            tail = reduce(tail, i, currPassword.size());
        }
        fout << tail << '\n';
    }
    fin.close();
    fout.close();
    return 0;
}

std::string string_to_hex(const std::string &input)
{
    static const char hex_digits[] = "0123456789ABCDEF";
    std::string output;
    output.reserve(input.length() * 2);
    for (unsigned char c : input)
    {
        output.push_back(hex_digits[c >> 4]);
        output.push_back(hex_digits[c & 15]);
    }
    return output;
}

std::string reduce(std::string hash, uint index, uint passwdSize)
{
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::string reducedPwd;
    std::string bytes{string_to_hex(hash)};
    //int n = (int)strtol(hash.c_str(), NULL, 16);
    int n;
    for (uint i{0}; i < passwdSize; i++)
    {
        n = bytes[(n + index) % 16];
        reducedPwd += chars[n % 62];
    }
    return reducedPwd;
}
