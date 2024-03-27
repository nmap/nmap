LINGUAS = $(patsubst %.po,%,$(wildcard *.po))

TOPDIR = ../../..
SOURCEFILES = zenmap
SOURCEDIRS = zenmapCore zenmapGUI radialnet
PROFILE_EDITOR_XML = share/zenmap/misc/profile_editor.xml

XGETTEXT = xgettext
MSGID_BUGS_ADDRESS = dev@nmap.org

ZENMAP_POT = zenmap.pot
TMP_POT = tmp.pot

TMP_PO = tmp.po

all:
	@echo 'Run "make update-pot" to update $(ZENMAP_POT).'
	@echo 'Run "make <XX>.po" to update <XX>.po from $(ZENMAP_POT).'
	@echo 'Run "make update-mo" to update all MO files from PO files.'

update-pot:
	(echo $(SOURCEFILES); cd $(TOPDIR) && find $(SOURCEDIRS) -name '*.py') \
	  | $(XGETTEXT) -D $(TOPDIR) --from-code=utf-8 --language=python --msgid-bugs-address=$(MSGID_BUGS_ADDRESS) -f - -o $(TMP_POT)
	./xgettext-profile_editor.py -D $(TOPDIR) $(PROFILE_EDITOR_XML) >> $(TMP_POT)
	msguniq --to-code=utf-8 $(TMP_POT) | msgmerge -U --backup=none $(ZENMAP_POT) -
	rm -f $(TMP_POT)

update-mo: $(addsuffix /LC_MESSAGES/zenmap.mo,$(LINGUAS))

%.po: $(ZENMAP_POT)
	cp -f $@ $(TMP_PO)
	msgmerge -N $(TMP_PO) $< | msgattrib --no-obsolete -o $@
	rm -f $(TMP_PO)

%/LC_MESSAGES/zenmap.mo: %.po
	mkdir -p $*/LC_MESSAGES
	msgfmt $< -o $@

.PHONY: update-pot
