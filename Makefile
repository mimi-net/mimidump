TARGET = mimidump

SHELL = /bin/sh

prefix = /usr/local
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = $(INSTALL)

CFLAGS = -Werror -Wall -Wextra -pedantic -pthread
LDFLAGS = -pthread
LDLIBS = -lpcap -lbsd

SOURCES = $(wildcard *.c)
OBJECTS = $(patsubst %.c,%.o,$(SOURCES))

.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJECTS): %.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

.PHONY: install
install: $(TARGET)
	$(INSTALL_PROGRAM) $(TARGET) $(DESTDIR)$(bindir)/$(TARGET)

.PHONY: install-strip
install-strip:
	$(MAKE) INSTALL_PROGRAM='$(INSTALL_PROGRAM) -s' install

.PHONY: clean
clean:
	$(RM) $(TARGET) $(OBJECTS)
