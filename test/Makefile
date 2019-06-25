LIBRHO= ../src/librho.a

CC= gcc -std=gnu99
CFLAGS = -I../src -Wall -Werror -Wextra

TESTS = \
		rho_array_test \
		rho_bitmap_test \
		rho_bitops_tes \
		rho_base32_test \
		rho_str_test

OBJS = rho_test.o $(addsuffix .o,$(TESTS))

all: $(TESTS)

rho_array_test: rho_array_test.o rho_test.o $(LIBRHO)
	$(CC) -o $@ $(CFLAGS) $^ $(LIBRHO) 

rho_bitmap_test: rho_bitmap_test.o rho_test.o $(LIBRHO)
	$(CC) -o $@ $(CFLAGS) $^ $(LIBRHO) 

rho_bitops_test: rho_bitops_test.o rho_test.o $(LIBRHO)
	$(CC) -o $@ $(CFLAGS) $^ $(LIBRHO) 

rho_base32_test: rho_base32_test.o rho_test.o $(LIBRHO)
	$(CC) -o $@ $(CFLAGS) $^ $(LIBRHO) 

rho_str_test: rho_str_test.o rho_test.o $(LIBRHO)
	$(CC) -o $@ $(CFLAGS) $^ $(LIBRHO) 

rho_test.o: rho_test.c
rho_array_test.o: rho_array_test.c
rho_base32_test.o: rho_base32_test.c
rho_bitmap_test.o: rho_bitmap_test.c
rho_bitops_test.o: rho_bitops_test.c
rho_str_test.o: rho_str_test.c

clean:
	rm -f $(TESTS) $(OBJS)

.PHONY: clean

# valgrind command line for memory leaks:
# 	valgrind --tool=memcheck --leak-check=yes --show-reachable=yes ./EXECUTABLE
