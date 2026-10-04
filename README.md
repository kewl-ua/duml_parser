# capdump

Focused DJI M4T/WA345T firmware dumper:

```text
USBPcap .pcap
   ↓
DUML reassembly + CRC validation
   ↓
General/0x2A FileTrans
   ↓
OPEN / DATA / END
   ↓
reconstructed .fw.sig / .cfg.sig
   ↓
size + MD5 verification
```

## Usage

```bash
make dump CAP=../captures/full_usb3.pcap
```

Custom output:

```bash
make dump CAP=../captures/full_usb3.pcap OUT=dump_m4t
```

Verify an existing dump:

```bash
make verify OUT=dump_m4t
```

Direct Python:

```bash
python capdump.py ../captures/full_usb3.pcap -o dump_m4t
```

Output:

```text
dump_m4t/
├── files/
│   ├── wa345t.cfg.sig
│   ├── wa345t.cfg.sig.duml.txt
│   ├── wa345t_0802_....fw.sig
│   └── ...
├── filetrans.txt
└── manifest.json
```

`capdump.py` exits non-zero when any transfer fails size/MD5 verification.
Use `--allow-partial` only when intentionally working with incomplete captures.
