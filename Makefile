all:

SDIR=/var/slimstk

# matches SFILES in inst-init
SFILES=slimstk.php slimstkcmd.php slimstkext.php slimstkcmdext.php \
	slimstk-login slimstk-status kms-decrypt

links:
	mkdir -p $(SDIR)
	for f in $(SFILES); do ln -sf `pwd`/$$f /var/slimstk; done
	ln -sf `pwd`/slimstk /usr/local/bin/slimstk

