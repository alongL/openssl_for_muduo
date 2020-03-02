XX = g++

CXXFLAGS =  -c  -g -std=c++11
CLIBS =  -L./lib -lmuduo_net -lmuduo_base  -lssl -lcrypto -ldl -lpthread
INCLUDE_DIRS = -I../

SRC=$(wildcard *.cpp)
OBJECTS:=$(patsubst %.cpp,%.o,$(SRC))

PROGRAM:= sslClient
TARGET = ./$(PROGRAM)



all:  $(TARGET)  


$(TARGET) : $(OBJECTS) 
	$(XX)   -o $(TARGET)  $(OBJECTS)  $(CLIBS)  


$(OBJECTS) : %.o : %.cpp 
	$(XX)  $(CXXFLAGS) $< -o $@ $(INCLUDE_DIRS) 




	
	

.PHONY : clean

clean:
	rm -rf $(TARGET) $(OBJECTS)