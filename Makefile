all: app print

.PHONY: app clean

APP_BIN=./app/target/debug/app

app:
	$(MAKE) -C app

clean:
	@rm -f print
	$(MAKE) -C app clean

print: CFLAGS += -static
print: print.c

run-print: print
	./print

save-print:
	@sudo $(APP_BIN) dump `pgrep print | tail -1` print.proc

restore-print:
	@sudo $(APP_BIN) restore print.proc
