CFLAGS = -g -Wall `pkg-config --cflags openssl`
#LIBS = `pkg-config --libs openssl`
LIBS = /home/pace/openssl-1.0.1f/libssl.a /home/pace/openssl-1.0.1f/libcrypto.a -ldl

all: slimstk-agent slimstk-decrypt

links:
	sudo rm -rf /opt/slimstk
	sudo ln -s `pwd` /opt/slimstk
	sudo rm -f /usr/local/bin/slimstk
	sudo ln -s `pwd`/slimstk /usr/local/bin/slimstk

slimstk-agent: slimstk-agent.o base64.o
	$(CC) $(CFLAGS) -o slimstk-agent slimstk-agent.o base64.o $(LIBS)

slimstk-decrypt: slimstk-decrypt.o
	$(CC) $(CFLAGS) -o slimstk-decrypt slimstk-decrypt.o

clean:
	rm -f ? *~ TMP.*
