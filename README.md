# Rainbow Attack

This project is the second homework that is made for the course of SECG4. The objective is to attack a password table with a rainbow attack.

## Introduction

A rainbow attack is an hacking method to find password from hashes. To do so, we use a rainbow table or also called, rainbow hash table.

This method allows us to crack password more quickly than the bruteforce way.

In this exercice:
- the hash function is SHA-256.
- passwords are not salted
- passwords are alphanumeric of length 6 to 8 included.
- passwords are stored after a simple pass through the hash function

## Installation

For this exercice, we used C++17 to code on Linux.
To do so, you need to install g++ ands the dependencies related to this package.

To start using this project you can first:
- Clone this repository and cd in it
- Next, you can build the project by running: `make`

## Use

To generate the rainbow table, you can run (after building the project of course):

`./rainbow -g <size>`, this will generate the `rb_table.txt` file of size `<size>`.

To proceed the attack on the previously generated table, you can run:

`./rainbow -a <your_hashes_file.txt>`, the program will check the success at the end of the attack.

To clean the project and all of the generated files, you can run:

`make clean`.

## Members : 

- Zakaria Bendaimi 54257
- Amine-Ayoub Bigham 54985
- Anas Ben Allal 53203
- Younes Afkari 52196