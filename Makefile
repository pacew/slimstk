all:

SDIR=/var/slimstk

# matches SFILES in inst-init
SFILES=slimstk.php slimstkcmd.php slimstkext.php \
	slimstk-login slimstk-status

links:
	mkdir -p $(SDIR)
	for f in $(SFILES); do ln -sf `pwd`/$$f /var/slimstk; done
	ln -sf `pwd`/slimstk /usr/local/bin/slimstk

