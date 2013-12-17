#!/usr/bin/env python

''' 
Download debugging symbols from the Microsoft Symbol Server. 
Can use as an input an executable file OR a GUID+Age and filename.
Examples:

$ python symcheck.py -e ntoskrnl.exe

$ python symchk.py -g 32962337f0f646388b39535cd8dd70e82 -s ntoskrnl.pdb
The GUID+Age here corresponds to the kernel version of the xp-laptop-2005-* images
The Age value is 0x2.


Module Dependencies:
This script requires the following modules:
pefile - http://code.google.com/p/pefile/
construct - http://construct.wikispaces.com/
To decompress downloaded files you should also have cabextract on your system.
http://www.cabextract.org.uk/

License: 
GPL version 3
http://www.gnu.org/licenses/gpl.html

Miscellaneous References:
You can see an explanation of the URL format at:
http://jimmers.info/pdb.html
'''

import urllib2
import sys,os
import os.path
import pdbparse
from pefile import PE
from shutil import copyfileobj
from urllib import FancyURLopener
from pdbparse.peinfo import *
from itertools import islice, count

#SYM_URL = 'http://symbols.mozilla.org/firefox'
SYM_URLS = ['http://msdl.microsoft.com/download/symbols']
USER_AGENT = "Microsoft-Symbol-Server/6.6.0007.5"

class PDBOpener(FancyURLopener):
    version = USER_AGENT
    def http_error_default(self, url, fp, errcode, errmsg, headers):
        if errcode == 404:
            raise urllib2.HTTPError(url, errcode, errmsg, headers, fp)
        else:
            FancyURLopener.http_error_default(url, fp, errcode, errmsg, headers)

lastprog = None
def progress(blocks,blocksz,totalsz):
    global lastprog
    if lastprog is None:
        print "Connected. Downloading data..."
    percent = int((100*(blocks*blocksz)/float(totalsz)))
    if lastprog != percent and percent % 5 == 0: print "%d%%" % percent,
    lastprog = percent
    sys.stdout.flush()

def download_file(guid,fname,path="",verbose=False):
    ''' 
    Download the symbols specified by guid and filename. Note that 'guid'
    must be the GUID from the executable with the dashes removed *AND* the
    Age field appended. The resulting file will be saved to the path argument,
    which default to the current directory.
    '''
    
    # A normal GUID is 32 bytes. With the age field appended
    # the GUID argument should therefore be longer to be valid.
    # Exception: old-style PEs without a debug section use 
    # TimeDateStamp+SizeOfImage
    if len(guid) == 32:
        print "Warning: GUID is too short to be valid. Did you append the Age field?"

    for sym_url in SYM_URLS:
        url = sym_url + "/%s/%s/" % (fname,guid)
        opener = urllib2.build_opener()
        
        # Whatever extension the user has supplied it must be replaced with .pd_
        tries = [ fname[:-1] + '_', fname ]

        for t in tries:
            if verbose: print "Trying %s" % (url+t)
            outfile = os.path.join(path,t)
            try:
                hook = None if not verbose else progress
                PDBOpener().retrieve(url+t, outfile, reporthook=hook)
                if verbose:
                    print
                    print "Saved symbols to %s" % (outfile)
                return outfile
            except urllib2.HTTPError, e:
                if verbose:
                    print "HTTP error %u" % (e.code)
    return None

def handle_pe(folder, pe_file):
    try:
        dbgdata, tp = get_pe_debug_data(pe_file)
    except:
        return

    pe_header =  PE(pe_file, fast_load=True)
    pe_guid = "%.8x%.5x" % (pe_header.FILE_HEADER.TimeDateStamp, pe_header.OPTIONAL_HEADER.SizeOfImage)
    # print "PE GUID: %s" % pe_guid
    if tp == "IMAGE_DEBUG_TYPE_CODEVIEW":
        # XP+
        if dbgdata[:4] == "RSDS":
            (guid,filename) = get_rsds(dbgdata)
        elif dbgdata[:4] == "NB10":
            (guid,filename) = get_nb10(dbgdata)
        else:
            print "ERR: CodeView section not NB10 or RSDS"
            return
        saved_file = download_file(guid.upper(),filename)
        pdb = "%s:%s:%s" % (filename, pe_guid, guid)
    elif tp == "IMAGE_DEBUG_TYPE_MISC":
        # Win2k
        # Get the .dbg file
        guid = get_pe_guid(pe_file)
        filename = get_dbg_fname(dbgdata)
        pdb = "%s:%s:%s" % (filename, pe_guid, guid)
        saved_file = download_file(guid.upper(),filename)

        # Extract it if it's compressed
        # Note: requires cabextract!
        if saved_file.endswith("_"):
            os.system("cabextract -q %s" % saved_file)
            saved_file = saved_file.replace('.db_','.dbg')

        from pdbparse.dbgold import DbgFile
        dbgfile = DbgFile.parse_stream(open(saved_file))
        cv_entry = [ d for d in dbgfile.IMAGE_DEBUG_DIRECTORY
                       if d.Type == "IMAGE_DEBUG_TYPE_CODEVIEW"][0]
        if cv_entry.Data[:4] == "NB09":
            return
        elif cv_entry.Data[:4] == "NB10":
            (guid,filename) = get_nb10(cv_entry.Data)
            
            guid = guid.upper()
            saved_file = download_file(guid,filename)
        else:
            print "WARN: DBG file received from symbol server has unknown CodeView section"
            return
    else:
        print "Unknown type:",tp
        return

    if saved_file.endswith("_"):
        os.system("cabextract -q %s" % saved_file)
        os.system("find . -maxdepth 1 -iname \"%s\" -exec rm {} \;" % saved_file)
        os.system("find . -maxdepth 1 -iname \"%s\" -exec mv {} ./%s/%s \;" % (filename, folder, pdb))
        print "%s" % pdb

def get_pe_from_pe(filename):
    guid = get_pe_guid(filename)
    symname = os.path.basename(filename)
    saved_file = download_file(guid, symname)
    if saved_file.endswith("_"):
        os.system("cabextract -q %s" % saved_file)

def main():
    global SYM_URLS
    handle_pe(sys.argv[1], sys.argv[2])
        
if __name__ == "__main__":
    main()
