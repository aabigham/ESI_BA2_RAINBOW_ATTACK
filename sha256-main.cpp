#include <iostream>
#include "sha256.h"

using std::cout;
using std::endl;
using std::string;

int main(int argc, char *argv[])
{
    string input = "grape";
    string output1 = sha256(input);

    cout << "sha256('" << input << "'):" << output1 << endl;
    return 0;
}
