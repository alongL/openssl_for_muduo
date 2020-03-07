XX = g++

CXXFLAGS =  -c  -g -std=c++11
CLIBS =  -L../lib -lmuduo_net -lmuduo_base  -lssl -lcrypto -ldl -lpthread
INCLUDE_DIRS = -I../include

SRC=$(wildcard *.cpp)
OBJECTS:=$(patsubst %.cpp,%.o,$(SRC))

SERVER:= sslServer
CLIENT = sslClient


all:  $(SERVER)   $(CLIENT)



$(OBJECTS) : %.o : %.cpp 
	$(XX)  $(CXXFLAGS) $< -o $@ $(INCLUDE_DIRS) 

$(CLIENT)  : $(OBJECTS) 
	$(XX)  -o $(CLIENT)  client.o cert.o  $(CLIBS)  


$(SERVER) : $(OBJECTS)
	$(XX)  -o $(SERVER) server.o  cert.o $(CLIBS)  
	
	

.PHONY : clean

clean:
	rm -rf $(CLIENT) $(OBJECTS) $(SERVER)