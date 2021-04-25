SRC = main.cpp sha256.cpp

all: rainbow

rainbow: $(SRC)
	g++ -std=c++17 -fsanitize=address -O2 -o $@ $^

clean:
	rm -rf rainbow pwd.txt hashes.txt rb_table.txt