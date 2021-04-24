COMMON = random.hpp sha256.cpp passwd-utils.hpp 
SRC_RAINBOW = main.cpp sha256.cpp passwd-utils.hpp

all: gen-passwd check-passwd rainbow

gen-passwd: gen-passwd.cpp $(COMMON)
	g++ -std=c++17 -fsanitize=address -o $@ $^

check-passwd: check-passwd.cpp $(COMMON)
	g++ -std=c++17 -fsanitize=address -o $@ $^

rainbow: $(SRC_RAINBOW)
	g++ -std=c++17 -fsanitize=address -o $@ $^

clean:
	rm -rf gen-passwd check-passwd rainbow *.txt