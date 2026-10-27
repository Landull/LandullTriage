"""
Read a file straight off an NTFS volume, bypassing Windows file locks.

Windows keeps some of the most useful evidence locked while it runs: registry hives
(SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT), Amcache.hve, SRUDB.dat, browser
databases, pagefile.sys, hiberfil.sys and swapfile.sys. Opening the volume itself
(\\\\.\\C:) as administrator and walking the MFT reads them anyway.

Pure Python, read-only. Supports resident and non-resident $DATA, sparse runs,
fragmented files whose runs spill into extension records ($ATTRIBUTE_LIST), and
large directories ($INDEX_ALLOCATION). NTFS-compressed and EFS-encrypted files are
refused rather than copied wrong.

Also usable against an image file: NTFSVolume(open("disk.raw", "rb"), offset=...).
"""

import os
import struct

ATTR_LIST, FILE_NAME, DATA, INDEX_ROOT, INDEX_ALLOC, REPARSE, END = 0x20, 0x30, 0x80, 0x90, 0xA0, 0xC0, 0xFFFFFFFF
# reparse tags whose real file content is NOT in the unnamed $DATA stream
REPARSE_NOT_IN_DATA = {0x80000017: "compressed by Windows (WOF/CompactOS)", 0x80000013: "deduplicated by Windows",
                       0x8000001B: "an AppExecLink alias"}
ROOT_RECORD = 5
CHUNK = 4 * 1024 * 1024


class NTFSError(Exception):
    pass


class _Reader:
    """Sector-aligned reads (raw Windows volume handles reject unaligned I/O)."""

    def __init__(self, fh, base=0, align=4096):
        self.fh, self.base, self.align = fh, base, align

    def read(self, offset, size):
        if size <= 0:
            return b""
        start = self.base + offset
        a0 = start - (start % self.align)
        end = start + size
        a1 = end + (-end % self.align)
        self.fh.seek(a0)
        buf = bytearray()
        need = a1 - a0
        while len(buf) < need:
            b = self.fh.read(need - len(buf))
            if not b:
                break
            buf += b
        return bytes(buf[start - a0:start - a0 + size])


def _fixup(buf, sector):
    buf = bytearray(buf)
    usa_off, usa_cnt = struct.unpack_from("<HH", buf, 4)
    if usa_cnt == 0:
        return bytes(buf)
    usn = buf[usa_off:usa_off + 2]
    for i in range(1, usa_cnt):
        pos = i * sector - 2
        if pos + 2 > len(buf):
            break
        if buf[pos:pos + 2] != usn:
            raise NTFSError("bad update sequence (torn or corrupt record)")
        buf[pos:pos + 2] = buf[usa_off + 2 * i:usa_off + 2 * i + 2]
    return bytes(buf)


def parse_runs(data):
    """Decode a runlist into [(lcn or None for sparse, length_in_clusters), ...]."""
    runs, pos, lcn = [], 0, 0
    while pos < len(data):
        hdr = data[pos]
        if hdr == 0:
            break
        ln_sz, off_sz = hdr & 0x0F, hdr >> 4
        pos += 1
        if ln_sz == 0:
            raise NTFSError("bad runlist")
        length = int.from_bytes(data[pos:pos + ln_sz], "little")
        pos += ln_sz
        if off_sz:
            delta = int.from_bytes(data[pos:pos + off_sz], "little", signed=True)
            pos += off_sz
            lcn += delta
            runs.append((lcn, length))
        else:
            runs.append((None, length))
    return runs


class Attr:
    __slots__ = ("type", "name", "resident", "flags", "value", "start_vcn", "last_vcn", "runs",
                 "real_size", "init_size", "alloc_size", "attr_id")

    def __init__(self, rec, off):
        (self.type, length, nonres, name_len, name_off, self.flags,
         self.attr_id) = struct.unpack_from("<IIBBHHH", rec, off)
        self.name = rec[off + name_off:off + name_off + 2 * name_len].decode("utf-16-le", "replace") if name_len else ""
        self.resident = not nonres
        self.value = None
        self.runs = []
        if self.resident:
            vlen, voff = struct.unpack_from("<IH", rec, off + 0x10)
            self.value = rec[off + voff:off + voff + vlen]
            self.real_size = self.init_size = self.alloc_size = vlen
            self.start_vcn = self.last_vcn = 0
        else:
            self.start_vcn, self.last_vcn = struct.unpack_from("<QQ", rec, off + 0x10)
            run_off = struct.unpack_from("<H", rec, off + 0x20)[0]
            self.alloc_size, self.real_size, self.init_size = struct.unpack_from("<QQQ", rec, off + 0x28)
            self.runs = parse_runs(rec[off + run_off:off + length])


class NTFSVolume:
    def __init__(self, fh, offset=0):
        self.r = _Reader(fh, offset, 512)
        boot = self.r.read(0, 512)
        if boot[3:11] != b"NTFS    ":
            raise NTFSError("not an NTFS volume")
        self.sector = struct.unpack_from("<H", boot, 0x0B)[0]
        spc = boot[0x0D]
        self.spc = spc if spc <= 0x80 else 1 << (256 - spc)
        self.cluster = self.sector * self.spc
        self.r.align = max(self.sector, 512)
        mft_lcn = struct.unpack_from("<Q", boot, 0x30)[0]
        cpr = struct.unpack_from("<b", boot, 0x40)[0]
        self.rec_size = (1 << -cpr) if cpr < 0 else cpr * self.cluster
        cpi = struct.unpack_from("<b", boot, 0x44)[0]
        self.idx_size = (1 << -cpi) if cpi < 0 else cpi * self.cluster
        # bootstrap: record 0 is $MFT itself, at mft_lcn
        rec0 = self._fix(self.r.read(mft_lcn * self.cluster, self.rec_size))
        self._mft_runs = None
        self._mft_runs = self._data_runs_from(0, rec0)

    # ---------------------------------------------------------- records
    def _fix(self, raw):
        if raw[:4] != b"FILE":
            raise NTFSError("bad MFT record signature")
        return _fixup(raw, self.sector)

    def _vcn_to_offset(self, runs, vcn):
        v = 0
        for lcn, ln in runs:
            if vcn < v + ln:
                if lcn is None:
                    return None
                return (lcn + (vcn - v)) * self.cluster
            v += ln
        raise NTFSError("offset beyond end of runlist")

    def record(self, num):
        byte = num * self.rec_size
        vcn, within = divmod(byte, self.cluster)
        if self.rec_size <= self.cluster:
            base = self._vcn_to_offset(self._mft_runs, vcn)
            raw = self.r.read(base + within, self.rec_size)
        else:  # record spans clusters that may not be contiguous
            raw = b""
            need = self.rec_size
            while need > 0:
                base = self._vcn_to_offset(self._mft_runs, vcn)
                take = min(need, self.cluster - within)
                raw += self.r.read(base + within, take)
                need -= take
                vcn += 1
                within = 0
        return self._fix(raw)

    def attrs(self, rec):
        off = struct.unpack_from("<H", rec, 0x14)[0]
        out = []
        while off + 8 <= len(rec):
            t, ln = struct.unpack_from("<II", rec, off)
            if t == END or ln == 0:
                break
            out.append(Attr(rec, off))
            off += ln
        return out

    def _all_attrs(self, num, rec=None):
        """Attributes of a file including those stored in extension records via $ATTRIBUTE_LIST."""
        rec = rec if rec is not None else self.record(num)
        attrs = self.attrs(rec)
        al = next((a for a in attrs if a.type == ATTR_LIST), None)
        if al is None:
            return attrs
        data = al.value if al.resident else self._read_runs(al.runs, al.real_size, al.init_size)
        ext = set()
        pos = 0
        while pos + 0x1A <= len(data):
            atype, rlen = struct.unpack_from("<IH", data, pos)
            if rlen == 0:
                break
            ref = struct.unpack_from("<Q", data, pos + 0x10)[0] & 0xFFFFFFFFFFFF
            if ref != num:
                ext.add(ref)
            pos += rlen
        for ref in sorted(ext):
            try:
                attrs.extend(self.attrs(self.record(ref)))
            except NTFSError:
                pass
        return [a for a in attrs if a.type != ATTR_LIST]

    def _data_runs_from(self, num, rec):
        parts = [a for a in self._all_attrs(num, rec) if a.type == DATA and a.name == "" and not a.resident]
        if not parts:
            raise NTFSError("no non-resident $DATA")
        parts.sort(key=lambda a: a.start_vcn)
        runs = []
        for a in parts:
            runs.extend(a.runs)
        return runs

    def _read_runs(self, runs, real_size, init_size=None):
        return b"".join(self._iter_runs(runs, real_size, init_size))

    def _iter_runs(self, runs, real_size, init_size=None, stop=None):
        init_size = real_size if init_size is None else min(init_size, real_size)
        pos = 0
        for lcn, ln in runs:
            nbytes = ln * self.cluster
            done = 0
            while done < nbytes and pos < real_size:
                if stop and stop():
                    raise NTFSError("stopped")
                take = min(CHUNK, nbytes - done, real_size - pos)
                if lcn is None or pos >= init_size:
                    chunk = b"\x00" * take
                else:
                    chunk = self.r.read(lcn * self.cluster + done, take)
                    if pos + take > init_size:  # bytes past the initialized size read as zero
                        keep = init_size - pos
                        chunk = chunk[:keep] + b"\x00" * (take - keep)
                yield chunk
                pos += take
                done += take
            if pos >= real_size:
                break
        if pos < real_size:
            yield b"\x00" * (real_size - pos)

    # ---------------------------------------------------------- directories
    @staticmethod
    def _entries(buf, start, end):
        """Yield (mft_ref, name, flags, subnode_vcn) from an index node."""
        pos = start
        while pos + 0x10 <= end:
            ref, elen, klen, flags = struct.unpack_from("<QHHI", buf, pos)
            if elen == 0:
                break
            name = None
            if klen >= 0x42 and not flags & 2:
                nlen = buf[pos + 0x10 + 0x40]
                name = buf[pos + 0x10 + 0x42:pos + 0x10 + 0x42 + 2 * nlen].decode("utf-16-le", "replace")
            yield ref & 0xFFFFFFFFFFFF, name, flags
            if flags & 2:
                break
            pos += elen

    def lookup(self, dir_num, name):
        want = name.casefold()
        attrs = self._all_attrs(dir_num)
        root = next((a for a in attrs if a.type == INDEX_ROOT and a.name == "$I30"), None)
        if root is None:
            raise NTFSError("not a directory")
        v = root.value
        hdr = 0x10
        eoff, tsize = struct.unpack_from("<II", v, hdr)
        for ref, nm, _ in self._entries(v, hdr + eoff, hdr + tsize):
            if nm is not None and nm.casefold() == want:
                return ref
        allocs = sorted((a for a in attrs if a.type == INDEX_ALLOC and a.name == "$I30"), key=lambda a: a.start_vcn)
        if not allocs:
            return None
        runs = [r for a in allocs for r in a.runs]
        size = max(a.real_size for a in allocs)
        blob = self._read_runs(runs, size)
        for off in range(0, len(blob) - self.idx_size + 1, self.idx_size):
            block = blob[off:off + self.idx_size]
            if block[:4] != b"INDX":
                continue
            try:
                block = _fixup(block, self.sector)
            except NTFSError:
                continue
            eoff, tsize = struct.unpack_from("<II", block, 0x18)
            for ref, nm, _ in self._entries(block, 0x18 + eoff, 0x18 + tsize):
                if nm is not None and nm.casefold() == want:
                    return ref
        return None

    def resolve(self, path):
        """Path relative to the volume root, e.g. 'Windows/System32/config/SYSTEM'."""
        num = ROOT_RECORD
        for part in [p for p in path.replace("\\", "/").split("/") if p]:
            nxt = self.lookup(num, part)
            if nxt is None:
                raise NTFSError(f"not found on volume: {part}")
            num = nxt
        return num

    # ---------------------------------------------------------- file data
    def open_data(self, num):
        """(size, iterator factory) for the unnamed $DATA stream of a record."""
        every = self._all_attrs(num)
        rp = next((a for a in every if a.type == REPARSE), None)
        if rp is not None:
            raw = rp.value if rp.resident else self._read_runs(rp.runs, rp.real_size, rp.init_size)
            tag = struct.unpack_from("<I", raw, 0)[0] if len(raw) >= 4 else 0
            why = REPARSE_NOT_IN_DATA.get(tag) or ("a cloud placeholder (OneDrive etc.)" if tag & 0xFFFF0FFF == 0x9000001A else "")
            if why:
                raise NTFSError(f"file is {why}; its bytes aren't in the normal data stream (read it the normal way)")
        attrs = [a for a in every if a.type == DATA and a.name == ""]
        if not attrs:
            raise NTFSError("file has no data stream")
        if any(a.flags & 0x0001 for a in attrs):
            raise NTFSError("file is NTFS-compressed; not supported")
        if any(a.flags & 0x4000 for a in attrs):
            raise NTFSError("file is EFS-encrypted; not supported")
        if attrs[0].resident:
            val = attrs[0].value
            return len(val), lambda stop=None: iter([val])
        attrs.sort(key=lambda a: a.start_vcn)
        first = attrs[0]
        runs = [r for a in attrs for r in a.runs]
        return first.real_size, lambda stop=None: self._iter_runs(runs, first.real_size, first.init_size, stop)


def raw_copy(src, dest, stop=None):
    """
    Copy a file on a local NTFS volume (Windows) by reading the volume directly.
    Needs administrator rights. Returns bytes written; raises on failure.
    """
    full = os.path.abspath(src)
    drive, rest = os.path.splitdrive(full)
    if not drive or len(drive) != 2:
        raise NTFSError("raw reads only work on local drive letters")
    with open("\\\\.\\" + drive, "rb", buffering=0) as fh:
        vol = NTFSVolume(fh)
        num = vol.resolve(rest)
        size, it = vol.open_data(num)
        written = 0
        with open(dest, "wb") as out:
            for chunk in it(stop):
                out.write(chunk)
                written += len(chunk)
        if written != size:
            raise NTFSError(f"short read ({written} of {size} bytes)")
        return written


def raw_size(src):
    """Size of a (possibly locked) file via the MFT, or None."""
    full = os.path.abspath(src)
    drive, rest = os.path.splitdrive(full)
    try:
        with open("\\\\.\\" + drive, "rb", buffering=0) as fh:
            vol = NTFSVolume(fh)
            return vol.open_data(vol.resolve(rest))[0]
    except Exception:
        return None
