COMMON = random.hpp sha256.cpp passwd-utils.hpp

all: gen-table gen-passwd check-passwd

gen-table: main.cpp $(COMMON)
	g++ -std=c++17 -fsanitize=address -o $@ $^

gen-passwd: gen-passwd.cpp $(COMMON)
	g++ -std=c++17 -fsanitize=address -o $@ $^

check-passwd: check-passwd.cpp $(COMMON)
	g++ -std=c++17 -fsanitize=address -o $@ $^

clean:
	rm -rf gen-passwd check-passwd