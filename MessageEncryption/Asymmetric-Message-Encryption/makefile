COMPILER_FLAGS=-std=c++11
INCLUDE_PATHS=-I../../deps/openssl-1.1.1e/include
LIBRARY_PATHS=-L../../deps/openssl-1.1.1e
LIBRARIES=-lcrypto -lpthread -lz -ldl
all:
	g++ $(COMPILER_FLAGS) main.cpp $(INCLUDE_PATHS) $(LIBRARY_PATHS) $(LIBRARIES)

clean:
	rm *.out
	clear
