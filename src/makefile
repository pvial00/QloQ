CC=gcc
CFLAGS=-lssl -lcrypto -std=c99 -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib 
TARGET=qloq-keygen
all: $(TARGET)

$(TARGET): qloq_keygen.c
	$(CC) $(CFLAGS) -o $(TARGET) qloq_keygen.c

clean:
	$(RM) $(TARGET)
