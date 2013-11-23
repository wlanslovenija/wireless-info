all: wireless-info

wireless-info: main.o
	$(CC) $(LDFLAGS) -o $@ $^ -lnl

%.o: %.c
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c -I. -o $@ $<

clean:
	rm -rf *.o wireless-info

