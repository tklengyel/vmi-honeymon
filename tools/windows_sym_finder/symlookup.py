#!/usr/bin/env python
import pdbparse
import sys, os
import string
from operator import itemgetter,attrgetter
from bisect import bisect_right
from pdbparse.undecorate import undecorate
from pdbparse.undname import undname
from itertools import islice, count

class DummyOmap(object):
    def remap(self, addr):
        return addr

class Lookup(object):
    def __init__(self, folder, pdbname):
        self.addrs = {}
        self._cache = {}

        not_found = []

        pdbbase = ".".join(os.path.basename(pdbname).split('.')[:-1])
        guids = pdbname.partition(":")[2]
        pe_guid = guids.partition(":")[0]
        pdb_guid = guids.partition(":")[2]

        if not os.path.exists("./%s/%s" % (folder, pdbname)):
            print "WARN: %s not found" % pdbname
        try:
            print "Loading symbols for %s..." % pdbbase
            # Do this the hard way to avoid having to load
            # the types stream in mammoth PDB files
            pdb = pdbparse.parse("./%s/%s" % (folder, pdbname), fast_load=True)
            pdb.STREAM_DBI.load()
            pdb._update_names()
            pdb.STREAM_GSYM = pdb.STREAM_GSYM.reload()
            pdb.STREAM_GSYM.load()
            pdb.STREAM_SECT_HDR = pdb.STREAM_SECT_HDR.reload()
            pdb.STREAM_SECT_HDR.load()
            # These are the dicey ones
            pdb.STREAM_OMAP_FROM_SRC = pdb.STREAM_OMAP_FROM_SRC.reload()
            pdb.STREAM_OMAP_FROM_SRC.load()
            pdb.STREAM_SECT_HDR_ORIG = pdb.STREAM_SECT_HDR_ORIG.reload()
            pdb.STREAM_SECT_HDR_ORIG.load()

        except:
            return

        try:
            sects = pdb.STREAM_SECT_HDR_ORIG.sections
            omap = pdb.STREAM_OMAP_FROM_SRC
        except AttributeError as e:
            # In this case there is no OMAP, so we use the given section
            # headers and use the identity function for omap.remap
            sects = pdb.STREAM_SECT_HDR.sections
            omap = DummyOmap()

        gsyms = pdb.STREAM_GSYM

        last_sect = max(sects, key=attrgetter('VirtualAddress'))
        limit = last_sect.VirtualAddress + last_sect.Misc.VirtualSize

        self.addrs[0,limit] = {}
        self.addrs[0,limit]['name'] = pdbbase
        self.addrs[0,limit]['addrs'] = []

        sym_counter = []
        specials = '@\':`~ <>*,?.'
        trans = string.maketrans(specials, '_'*len(specials))

        counter = 0;

        header = open("%s.h" % pdbbase.translate(trans), 'w')
        header.write("static char *%s_%s_guid[2] = {\n\t\"%s\",\n\t\"%s\"\n\t};\n" %(folder, pdbbase.translate(trans), pe_guid, pdb_guid))
        header.write("static struct symbol %s_%s[] = {\n" % (folder, pdbbase.translate(trans)))

        for sym in gsyms.globals:

            if not hasattr(sym, 'offset'):
                print "No offset attribute"
                continue

            off = sym.offset
            try:
                virt_base = sects[sym.segment-1].VirtualAddress
            except IndexError:
                print "IndexError"
                continue

            mapped = omap.remap(off+virt_base)
            sym_name = sym.name
            if sym_name.startswith("?"):
                sym_name = undname(sym_name)

            sym_name = sym_name.translate(trans)

            sym_counter.append(sym_name);
            occurance = sym_counter.count(sym_name);

            if occurance > 1:
                sym_name += "_%u" % occurance

            if mapped > 0:
                counter = counter +1
                header.write("\t{.name = \"%s\", .rva = 0x%lx},\n" % (sym_name, mapped))

        header.write("\n};\n");
        header.write("static uint64_t %s_%s_count = %u;\n" %(folder, pdbbase.translate(trans), counter))
        header.close()
        print "\tSymbols found: %u" % counter

if __name__ == "__main__":
    lobj = Lookup(sys.argv[1], sys.argv[2])
