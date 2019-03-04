LIBRHO= ../src/librho.a
LIBRHO_HEADERS = ../src

TESTS = \
		rho_array_test

rho_array_test: rho_array_test.c $(LIBRHO)
	$(CC) -o $@ $^ -I $(LIBRHO_HEADERS) 

clean:
	rm -f $(TESTS)

.PHONY: clean

# valgrind command line for memory leaks:
# 	valgrind --tool=memcheck --leak-check=es --show-reachable=yes ./EXECUTABLE
