all:

install-links:
	mkdir -p /var/slimstk
	ln -sf `pwd`/slimstk.php /var/slimstk/slimstk.php
	ln -sf `pwd`/slimstk-login /usr/local/bin/slimstk-login
