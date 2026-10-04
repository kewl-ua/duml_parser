# DJI M4T / WA345T USBPcap firmware dumper
#
# Examples:
#   make dump CAP=../captures/full_usb3.pcap
#   make dump CAP=../captures/full_usb3.pcap OUT=dump_m4t
#   make verify OUT=dump_m4t
#
# On Windows/MSYS/Git Bash prefer forward slashes in CAP/OUT paths.

PYTHON ?= python
CAP ?=
OUT ?= dump
PROGRESS ?= 1

CAPDUMP := capdump.py
CORE := duml_semantic_v8.py
MANIFEST := $(OUT)/manifest.json

.PHONY: help dump verify clean check

help:
	@$(PYTHON) -c "print('Targets:'); print('  make dump CAP=<capture.pcap> [OUT=dump]'); print('  make verify [OUT=dump]'); print('  make check'); print('  make clean [OUT=dump]')"

dump:
	@$(PYTHON) -c "import sys; sys.exit(0 if len(sys.argv) > 1 and sys.argv[1] else 2)" "$(CAP)" || (echo "ERROR: CAP is required. Example: make dump CAP=../captures/full_usb3.pcap" && exit 2)
	$(PYTHON) $(CAPDUMP) "$(CAP)" -o "$(OUT)" --progress-interval $(PROGRESS)

verify:
	$(PYTHON) -c "import json,sys,pathlib; p=pathlib.Path('$(MANIFEST)'); m=json.loads(p.read_text(encoding='utf-8')); f=m['filetrans']; print('verified=%s/%s all_verified=%s' % (f['verified_transfers'], f['transfers'], f['all_verified'])); sys.exit(0 if f['all_verified'] else 1)"

check:
	$(PYTHON) -m py_compile $(CAPDUMP) $(CORE)
	$(PYTHON) $(CAPDUMP) --help

clean:
	$(PYTHON) -c "import shutil; shutil.rmtree('$(OUT)', ignore_errors=True); print('removed $(OUT)')"
