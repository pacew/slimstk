all:

links:
	sudo rm -rf /opt/slimstk
	sudo ln -s `pwd` /opt/slimstk
	sudo rm -f /usr/local/bin/slimstk
	sudo ln -s `pwd`/slimstk /usr/local/bin/slimstk

clean:
	rm -f ? *~ TMP.*
