CXX = g++
CXXFLAGS = -std=c++20 -O2 -Wall
LIBS = -lncurses -lcurl -lsecp256k1 -lcrypto

SRCS = main.cpp wallet.cpp ui.cpp coldwallet.cpp metadata.cpp utils.cpp
OBJS = $(SRCS:.cpp=.o)

bitcoinwallet: $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f *.o bitcoinwallet

