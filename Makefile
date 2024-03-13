TARGET = mimidump

CFLAGS = -Wall -Wextra -pedantic -pthread
LDFLAGS = -pthread
LDLIBS = -lpcap -lbsd

SOURCES = $(wildcard *.c)
OBJECTS = $(patsubst %.c,%.o,$(SOURCES))

.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS)
	cp $@ /usr/bin/ 

$(OBJECTS): %.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

.PHONY: clean
clean:
	$(RM) $(TARGET) $(OBJECTS)
