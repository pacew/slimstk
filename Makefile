all:

links:
	sudo ln -sf `pwd` /opt/slimstk
	sudo ln -sf `pwd`/slimstk /usr/local/bin/slimstk

clean:
	rm -f ? *~ TMP.*
