all:

SDIR=/var/slimstk

# matches SFILES in inst-init
SFILES=slimstk.php slimstkapp.php slimstk-login slimstk-status slimstk-install

links:
	mkdir -p $(SDIR)
	for f in $(SFILES); do ln -sf `pwd`/$$f /var/slimstk; done
	ln -sf `pwd`/slimstk /usr/local/bin/slimstk

