TARGET = apfspoc
CFLAGS = -O2 -Wall -Werror
SOURCES = main.c
FRAMEWORKS = -framework IOKit

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(FRAMEWORKS) -o $@ $(SOURCES)

clean:
	rm -f -- $(TARGET)
