CFLAGS = -g -Wall `pkg-config --cflags openssl`
LIBS = `pkg-config --libs openssl`

all: slimstk-agent

links:
	sudo rm -rf /opt/slimstk
	sudo ln -s `pwd` /opt/slimstk
	sudo rm -f /usr/local/bin/slimstk
	sudo ln -s `pwd`/slimstk /usr/local/bin/slimstk

slimstk-agent: slimstk-agent.o base64.o
	$(CC) $(CFLAGS) -o slimstk-agent slimstk-agent.o base64.o $(LIBS)

clean:
	rm -f ? *~ TMP.*
