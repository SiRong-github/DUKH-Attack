CC=gcc
CFLAGS=-Wall -g
EXE=program
OBJ=aes.o a1grader.o

$(EXE): program.c program.o $(OBJ)
	$(CC) $(CFLAGS) -o $(EXE) $< $(OBJ) -lm

%.o: %.c %.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(EXE)