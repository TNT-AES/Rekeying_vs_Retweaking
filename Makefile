objects = test.o timing.o TNT_AES.o
CC = g++ --std=c++11 -maes -O3

TNT_AES_Timing : main.cpp timing.cpp test.cpp TNT_AES.cpp
	$(CC) -c TNT_AES.cpp -o TNT_AES.o
	$(CC) -c timing.cpp -o timing.o
	$(CC) -c test.cpp -o test.o
	$(CC) main.cpp test.o timing.o TNT_AES.o -o TNT_AES_Timing

clean:
	rm $(objects)