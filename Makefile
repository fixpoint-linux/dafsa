.PHONY: test clean sync

dafsa: dafsa_test.c dafsa.c dafsa.h
	cosmocc -Wall -Wextra -Werror -O2 -o dafsa dafsa_test.c dafsa.c

test: dafsa
	./dafsa

clean:
	rm -f dafsa dafsa.dot

sync: dafsa.c dafsa.h
	mkdir -p /home/arch/projects/palimpsest/fst-indexer/c/
	cp dafsa.c dafsa.h /home/arch/projects/palimpsest/fst-indexer/c/
