ip-cidr-parser: ip-cidr-parser.o
	$(CC) -g -o $@ $<

ip-cidr-parser.o: ip-cidr-parser.c
	$(CC) -DDEBUG -g -c -o $@ $<

.PHONY: clean dist-clean

clean:
	-rm *.o

distclean: clean
	rm ip-cidr-parser
