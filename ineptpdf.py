#! /usr/bin/python

# ineptpdf8.4.52.pyw
# ineptpdf, version 8.4.52

# To run this program install Python 2.7 from http://w...content-available-to-author-only...n.org/download/ 
#
# PyCrypto from http://w...content-available-to-author-only...g.uk/python/modules.shtml#pycrypto
#
# and PyWin Extension (Win32API module) from
# http://s...content-available-to-author-only...e.net/projects/pywin32/files/
#
# Make sure to install the dedicated versions for Python 2.7.
# 
# It's recommended to use the 32-Bit Python Windows versions (even with a 64-bit
# Windows system).
#
# Save this script file as
# ineptpdf8.4.52.pyw and double-click on it to run it.

# Revision history:
#   1 - Initial release
#   2 - Improved determination of key-generation algorithm
#   3 - Correctly handle PDF >=1.5 cross-reference streams
#   4 - Removal of ciando's personal ID (anon)
#   5 - removing small bug with V3 ebooks (anon)
#   6 - changed to adeptkey4.der format for 1.7.2 support (anon)
#   6.1 - backward compatibility for 1.7.1 and old adeptkey.der (anon)
#   7 - Get cross reference streams and object streams working for input.
#       Not yet supported on output but this only effects file size,
#       not functionality. (anon2)
#   7.1 - Correct a problem when an old trailer is not followed by startxref (anon2)
#   7.2 - Correct malformed Mac OS resource forks for Stanza
#       - Support for cross ref streams on output (decreases file size) (anon2)
#   7.3 - Correct bug in trailer with cross ref stream that caused the error (anon2)
#         "The root object is missing or invalid" in Adobe Reader.
#   7.4 - Force all generation numbers in output file to be 0, like in v6.
#         Fallback code for wrong xref improved (search till last trailer
#         instead of first) (anon2)
#   8 - fileopen user machine identifier support (Tetrachroma)
#   8.1 - fileopen user cookies support (Tetrachroma)
#   8.2 - fileopen user name/password support (Tetrachroma)
#   8.3 - fileopen session cookie support (Tetrachroma)
#   8.3.1 - fix for the "specified key file does not exist" error (Tetrachroma)
#   8.3.2 - improved server result parsing (Tetrachroma)
#   8.4 - Ident4D and encrypted Uuid support (Tetrachroma)
#   8.4.1 - improved MAC address processing (Tetrachroma)
#   8.4.2 - FowP3Uuid fallback file processing (Tetrachroma)
#   8.4.3 - improved user/password pdf file detection (Tetrachroma)
#   8.4.4 - small bugfix (Tetrachroma)
#   8.4.5 - improved cookie host searching (Tetrachroma)
#   8.4.6 - STRICT parsing disabled (non-standard pdf processing) (Tetrachroma)
#   8.4.7 - UTF-8 input file conversion (Tetrachroma)
#   8.4.8 - fix for more rare utf8 problems (Tetrachroma)
#   8.4.9 - solution for utf8 in comination with
#           ident4id method (Tetrachroma)
#   8.4.10 - line feed processing, non c system drive patch, nrbook support (Tetrachroma)
#   8.4.11 - alternative ident4id calculation (Tetrachroma)
#   8.4.12 - fix for capital username characters and
#            other unusual user login names (Tetrachroma & ZeroPoint)
#   8.4.13 - small bug fixes (Tetrachroma)
#   8.4.14 - fix for non-standard-conform fileopen pdfs (Tetrachroma)
#   8.4.15 - 'bad file descriptor'-fix (Tetrachroma)
#   8.4.16 - improves user/pass detection (Tetrachroma)
#   8.4.17 - fix for several '=' chars in a DPRM entity (Tetrachroma)
#   8.4.18 - follow up bug fix for the DPRM problem,
#            more readable error messages (Tetrachroma)
#   8.4.19 - 2nd fix for 'bad file descriptor' problem (Tetrachroma)
#   8.4.20 - follow up patch (Tetrachroma)
#   8.4.21 - 3rd patch for 'bad file descriptor' (Tetrachroma)
#   8.4.22 - disable prints for exception prevention (Tetrachroma)
#   8.4.23 - check for additional security attributes (Tetrachroma)
#   8.4.24 - improved cookie session support (Tetrachroma)
#   8.4.25 - more compatibility with unicode files (Tetrachroma)
#   8.4.26 - automated session/user cookie request function (works
#            only with Firefox 3.x+) (Tetrachroma)
#   8.4.27 - user/password fallback
#   8.4.28 - AES decryption, improved misconfigured pdf handling,
#            limited experimental APS support (Tetrachroma & Neisklar)
#   8.4.29 - backport for bad formatted rc4 encrypted pdfs (Tetrachroma)
#   8.4.30 - extended authorization attributes support (Tetrachroma)
#   8.4.31 - improved session cookie and better server response error
#            handling (Tetrachroma)
#   8.4.33 - small cookie optimizations (Tetrachroma)
#   8.4.33 - debug output option (Tetrachroma)
#   8.4.34 - better user/password management
#            handles the 'AskUnp' response) (Tetrachroma)
#   8.4.35 - special handling for non-standard systems (Tetrachroma)
#   8.4.36 - previous machine/disk handling [PrevMach/PrevDisk] (Tetrachroma)
#   8.4.36 - FOPN_flock support (Tetrachroma)
#   8.4.37 - patch for unicode paths/filenames (Tetrachroma)
#   8.4.38 - small fix for user/password dialog (Tetrachroma)
#   8.4.39 - sophisticated request mode differentiation, forced
#            uuid calculation (Tetrachroma)
#   8.4.40 - fix for non standard server responses (Tetrachroma)
#   8.4.41 - improved user/password request windows,
#            better server response tolerance (Tetrachroma)
#   8.4.42 - improved nl/cr server response parsing (Tetrachroma)
#   8.4.43 - fix for user names longer than 13 characters and special
#            uuid encryption (Tetrachroma)
#   8.4.44 - another fix for ident4d problem (Tetrachroma)
#   8.4.45 - 2nd fix for ident4d problem (Tetrachroma)
#   8.4.46 - script cleanup and optimizations (Tetrachroma)
#   8.4.47 - script identification change to Adobe Reader (Tetrachroma)
#   8.4.48 - improved tolerance for false file/registry entries (Tetrachroma)
#   8.4.49 - improved username encryption (Tetrachroma)
#   8.4.50 - improved (experimental) APS support (Tetrachroma & Neisklar)
#   8.4.51 - automatic APS offline key retrieval (works only for
#            Onleihe right now) (80ka80 & Tetrachroma)
#   8.4.52 - fixed linux support (mazdac) - gets mac from eth0, if doesn't work change hardcodedinterface

"""
Decrypts Adobe ADEPT-encrypted and Fileopen PDF files.
"""

from __future__ import with_statement

__license__ = 'GPL v3'

import sys
import os
import re
import zlib
import struct
import hashlib
from itertools import chain, islice
import xml.etree.ElementTree as etree
import Tkinter
import Tkconstants
import tkFileDialog
import tkMessageBox
# added for fileopen support
import urllib
import urlparse
import time
import socket
import string
import uuid
import subprocess
import time
import getpass
from ctypes import *
import traceback
import inspect
import tempfile
import sqlite3
import httplib
try:
    from Crypto.Cipher import ARC4
    # needed for newer pdfs
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    
except ImportError:
    ARC4 = None
    RSA = None
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

class ADEPTError(Exception):
    pass

# global variable (needed for fileopen and password decryption)
INPUTFILEPATH = ''
KEYFILEPATH = ''
PASSWORD = ''
DEBUG_MODE = False
IVERSION = '8.4.52'
INTERFACE = 'eth0'

# Do we generate cross reference streams on output?
# 0 = never
# 1 = only if present in input
# 2 = always

GEN_XREF_STM = 1

# This is the value for the current document
gen_xref_stm = False # will be set in PDFSerializer

### 
### ASN.1 parsing code from tlslite

def bytesToNumber(bytes):
    total = 0L
    for byte in bytes:
        total = (total << 8) + byte
    return total

class ASN1Error(Exception):
    pass

class ASN1Parser(object):
    class Parser(object):
        def __init__(self, bytes):
            self.bytes = bytes
            self.index = 0
    
        def get(self, length):
            if self.index + length > len(self.bytes):
                raise ASN1Error("Error decoding ASN.1")
            x = 0
            for count in range(length):
                x <<= 8
                x |= self.bytes[self.index]
                self.index += 1
            return x
    
        def getFixBytes(self, lengthBytes):
            bytes = self.bytes[self.index : self.index+lengthBytes]
            self.index += lengthBytes
            return bytes
    
        def getVarBytes(self, lengthLength):
            lengthBytes = self.get(lengthLength)
            return self.getFixBytes(lengthBytes)
    
        def getFixList(self, length, lengthList):
            l = [0] * lengthList
            for x in range(lengthList):
                l[x] = self.get(length)
            return l
    
        def getVarList(self, length, lengthLength):
            lengthList = self.get(lengthLength)
            if lengthList % length != 0:
                raise ASN1Error("Error decoding ASN.1")
            lengthList = int(lengthList/length)
            l = [0] * lengthList
            for x in range(lengthList):
                l[x] = self.get(length)
            return l
    
        def startLengthCheck(self, lengthLength):
            self.lengthCheck = self.get(lengthLength)
            self.indexCheck = self.index
    
        def setLengthCheck(self, length):
            self.lengthCheck = length
            self.indexCheck = self.index
    
        def stopLengthCheck(self):
            if (self.index - self.indexCheck) != self.lengthCheck:
                raise ASN1Error("Error decoding ASN.1")
    
        def atLengthCheck(self):
            if (self.index - self.indexCheck) < self.lengthCheck:
                return False
            elif (self.index - self.indexCheck) == self.lengthCheck:
                return True
            else:
                raise ASN1Error("Error decoding ASN.1")

    def __init__(self, bytes):
        p = self.Parser(bytes)
        p.get(1)
        self.length = self._getASN1Length(p)
        self.value = p.getFixBytes(self.length)

    def getChild(self, which):
        p = self.Parser(self.value)
        for x in range(which+1):
            markIndex = p.index
            p.get(1)
            length = self._getASN1Length(p)
            p.getFixBytes(length)
        return ASN1Parser(p.bytes[markIndex:p.index])

    def _getASN1Length(self, p):
        firstLength = p.get(1)
        if firstLength<=127:
            return firstLength
        else:
            lengthLength = firstLength & 0x7F
            return p.get(lengthLength)

###
### PDF parsing routines from pdfminer, with changes for EBX_HANDLER

##  Utilities
##
def choplist(n, seq):
    '''Groups every n elements of the list.'''
    r = []
    for x in seq:
        r.append(x)
        if len(r) == n:
            yield tuple(r)
            r = []
    return

def nunpack(s, default=0):
    '''Unpacks up to 4 bytes big endian.'''
    l = len(s)
    if not l:
        return default
    elif l == 1:
        return ord(s)
    elif l == 2:
        return struct.unpack('>H', s)[0]
    elif l == 3:
        return struct.unpack('>L', '\x00'+s)[0]
    elif l == 4:
        return struct.unpack('>L', s)[0]
    else:
        return TypeError('invalid length: %d' % l)


STRICT = 0


##  PS Exceptions
##
class PSException(Exception): pass
class PSEOF(PSException): pass
class PSSyntaxError(PSException): pass
class PSTypeError(PSException): pass
class PSValueError(PSException): pass


##  Basic PostScript Types
##

# PSLiteral
class PSObject(object): pass

class PSLiteral(PSObject):
    '''
    PS literals (e.g. "/Name").
    Caution: Never create these objects directly.
    Use PSLiteralTable.intern() instead.
    '''
    def __init__(self, name):
        self.name = name
        return
    
    def __repr__(self):
        name = []
        for char in self.name:
            if not char.isalnum():
                char = '#%02x' % ord(char)
            name.append(char)
        return '/%s' % ''.join(name)

# PSKeyword
class PSKeyword(PSObject):
    '''
    PS keywords (e.g. "showpage").
    Caution: Never create these objects directly.
    Use PSKeywordTable.intern() instead.
    '''
    def __init__(self, name):
        self.name = name
        return
    
    def __repr__(self):
        return self.name

# PSSymbolTable
class PSSymbolTable(object):
    
    '''
    Symbol table that stores PSLiteral or PSKeyword.
    '''
    
    def __init__(self, classe):
        self.dic = {}
        self.classe = classe
        return
    
    def intern(self, name):
        if name in self.dic:
            lit = self.dic[name]
        else:
            lit = self.classe(name)
            self.dic[name] = lit
        return lit

PSLiteralTable = PSSymbolTable(PSLiteral)
PSKeywordTable = PSSymbolTable(PSKeyword)
LIT = PSLiteralTable.intern
KWD = PSKeywordTable.intern
KEYWORD_BRACE_BEGIN = KWD('{')
KEYWORD_BRACE_END = KWD('}')
KEYWORD_ARRAY_BEGIN = KWD('[')
KEYWORD_ARRAY_END = KWD(']')
KEYWORD_DICT_BEGIN = KWD('<<')
KEYWORD_DICT_END = KWD('>>')


def literal_name(x):
    if not isinstance(x, PSLiteral):
        if STRICT:
            raise PSTypeError('Literal required: %r' % x)
        else:
            return str(x)
    return x.name

def keyword_name(x):
    if not isinstance(x, PSKeyword):
        if STRICT:
            raise PSTypeError('Keyword required: %r' % x)
        else:
            return str(x)
    return x.name


##  PSBaseParser
##
EOL = re.compile(r'[\r\n]')
SPC = re.compile(r'\s')
NONSPC = re.compile(r'\S')
HEX = re.compile(r'[0-9a-fA-F]')
END_LITERAL = re.compile(r'[#/%\[\]()<>{}\s]')
END_HEX_STRING = re.compile(r'[^\s0-9a-fA-F]')
HEX_PAIR = re.compile(r'[0-9a-fA-F]{2}|.')
END_NUMBER = re.compile(r'[^0-9]')
END_KEYWORD = re.compile(r'[#/%\[\]()<>{}\s]')
END_STRING = re.compile(r'[()\134]')
OCT_STRING = re.compile(r'[0-7]')
ESC_STRING = { 'b':8, 't':9, 'n':10, 'f':12, 'r':13, '(':40, ')':41, '\\':92 }

class PSBaseParser(object):

    '''
    Most basic PostScript parser that performs only basic tokenization.
    '''
    BUFSIZ = 4096

    def __init__(self, fp):
        self.fp = fp
        self.seek(0)
        return

    def __repr__(self):
        return '<PSBaseParser: %r, bufpos=%d>' % (self.fp, self.bufpos)

    def flush(self):
        return
    
    def close(self):
        self.flush()
        return
    
    def tell(self):
        return self.bufpos+self.charpos

    def poll(self, pos=None, n=80):
        pos0 = self.fp.tell()
        if not pos:
            pos = self.bufpos+self.charpos
        self.fp.seek(pos)
        ##print >>sys.stderr, 'poll(%d): %r' % (pos, self.fp.read(n))
        self.fp.seek(pos0)
        return

    def seek(self, pos):
        '''
        Seeks the parser to the given position.
        '''
        self.fp.seek(pos)
        # reset the status for nextline()
        self.bufpos = pos
        self.buf = ''
        self.charpos = 0
        # reset the status for nexttoken()
        self.parse1 = self.parse_main
        self.tokens = []
        return

    def fillbuf(self):
        if self.charpos < len(self.buf): return
        # fetch next chunk.
        self.bufpos = self.fp.tell()
        self.buf = self.fp.read(self.BUFSIZ)
        if not self.buf:
            raise PSEOF('Unexpected EOF')
        self.charpos = 0
        return
    
    def parse_main(self, s, i):
        m = NONSPC.search(s, i)
        if not m:
            return (self.parse_main, len(s))
        j = m.start(0)
        c = s[j]
        self.tokenstart = self.bufpos+j
        if c == '%':
            self.token = '%'
            return (self.parse_comment, j+1)
        if c == '/':
            self.token = ''
            return (self.parse_literal, j+1)
        if c in '-+' or c.isdigit():
            self.token = c
            return (self.parse_number, j+1)
        if c == '.':
            self.token = c
            return (self.parse_float, j+1)
        if c.isalpha():
            self.token = c
            return (self.parse_keyword, j+1)
        if c == '(':
            self.token = ''
            self.paren = 1
            return (self.parse_string, j+1)
        if c == '<':
            self.token = ''
            return (self.parse_wopen, j+1)
        if c == '>':
            self.token = ''
            return (self.parse_wclose, j+1)
        self.add_token(KWD(c))
        return (self.parse_main, j+1)
                            
    def add_token(self, obj):
        self.tokens.append((self.tokenstart, obj))
        return
    
    def parse_comment(self, s, i):
        m = EOL.search(s, i)
        if not m:
            self.token += s[i:]
            return (self.parse_comment, len(s))
        j = m.start(0)
        self.token += s[i:j]
        # We ignore comments.
        #self.tokens.append(self.token)
        return (self.parse_main, j)
    
    def parse_literal(self, s, i):
        m = END_LITERAL.search(s, i)
        if not m:
            self.token += s[i:]
            return (self.parse_literal, len(s))
        j = m.start(0)
        self.token += s[i:j]
        c = s[j]
        if c == '#':
            self.hex = ''
            return (self.parse_literal_hex, j+1)
        self.add_token(LIT(self.token))
        return (self.parse_main, j)
    
    def parse_literal_hex(self, s, i):
        c = s[i]
        if HEX.match(c) and len(self.hex) < 2:
            self.hex += c
            return (self.parse_literal_hex, i+1)
        if self.hex:
            self.token += chr(int(self.hex, 16))
        return (self.parse_literal, i)

    def parse_number(self, s, i):
        m = END_NUMBER.search(s, i)
        if not m:
            self.token += s[i:]
            return (self.parse_number, len(s))
        j = m.start(0)
        self.token += s[i:j]
        c = s[j]
        if c == '.':
            self.token += c
            return (self.parse_float, j+1)
        try:
            self.add_token(int(self.token))
        except ValueError:
            pass
        return (self.parse_main, j)
    def parse_float(self, s, i):
        m = END_NUMBER.search(s, i)
        if not m:
            self.token += s[i:]
            return (self.parse_float, len(s))
        j = m.start(0)
        self.token += s[i:j]
        self.add_token(float(self.token))
        return (self.parse_main, j)
    
    def parse_keyword(self, s, i):
        m = END_KEYWORD.search(s, i)
        if not m:
            self.token += s[i:]
            return (self.parse_keyword, len(s))
        j = m.start(0)
        self.token += s[i:j]
        if self.token == 'true':
            token = True
        elif self.token == 'false':
            token = False
        else:
            token = KWD(self.token)
        self.add_token(token)
        return (self.parse_main, j)

    def parse_string(self, s, i):
        m = END_STRING.search(s, i)
        if not m:
            self.token += s[i:]
            return (self.parse_string, len(s))
        j = m.start(0)
        self.token += s[i:j]
        c = s[j]
        if c == '\\':
            self.oct = ''
            return (self.parse_string_1, j+1)
        if c == '(':
            self.paren += 1
            self.token += c
            return (self.parse_string, j+1)
        if c == ')':
            self.paren -= 1
            if self.paren:
                self.token += c
                return (self.parse_string, j+1)
        self.add_token(self.token)
        return (self.parse_main, j+1)
    def parse_string_1(self, s, i):
        c = s[i]
        if OCT_STRING.match(c) and len(self.oct) < 3:
            self.oct += c
            return (self.parse_string_1, i+1)
        if self.oct:
            self.token += chr(int(self.oct, 8))
            return (self.parse_string, i)
        if c in ESC_STRING:
            self.token += chr(ESC_STRING[c])
        return (self.parse_string, i+1)

    def parse_wopen(self, s, i):
        c = s[i]
        if c.isspace() or HEX.match(c):
            return (self.parse_hexstring, i)
        if c == '<':
            self.add_token(KEYWORD_DICT_BEGIN)
            i += 1
        return (self.parse_main, i)

    def parse_wclose(self, s, i):
        c = s[i]
        if c == '>':
            self.add_token(KEYWORD_DICT_END)
            i += 1
        return (self.parse_main, i)

    def parse_hexstring(self, s, i):
        m = END_HEX_STRING.search(s, i)
        if not m:
            self.token += s[i:]
            return (self.parse_hexstring, len(s))
        j = m.start(0)
        self.token += s[i:j]
        token = HEX_PAIR.sub(lambda m: chr(int(m.group(0), 16)),
                                                 SPC.sub('', self.token))
        self.add_token(token)
        return (self.parse_main, j)

    def nexttoken(self):
        while not self.tokens:
            self.fillbuf()
            (self.parse1, self.charpos) = self.parse1(self.buf, self.charpos)
        token = self.tokens.pop(0)
        return token

    def nextline(self):
        '''
        Fetches a next line that ends either with \\r or \\n.
        '''
        linebuf = ''
        linepos = self.bufpos + self.charpos
        eol = False
        while 1:
            self.fillbuf()
            if eol:
                c = self.buf[self.charpos]
                # handle '\r\n'
                if c == '\n':
                    linebuf += c
                    self.charpos += 1
                break
            m = EOL.search(self.buf, self.charpos)
            if m:
                linebuf += self.buf[self.charpos:m.end(0)]
                self.charpos = m.end(0)
                if linebuf[-1] == '\r':
                    eol = True
                else:
                    break
            else:
                linebuf += self.buf[self.charpos:]
                self.charpos = len(self.buf)
        return (linepos, linebuf)

    def revreadlines(self):
        '''
        Fetches a next line backword. This is used to locate
        the trailers at the end of a file.
        '''
        self.fp.seek(0, 2)
        pos = self.fp.tell()
        buf = ''
        while 0 < pos:
            prevpos = pos
            pos = max(0, pos-self.BUFSIZ)
            self.fp.seek(pos)
            s = self.fp.read(prevpos-pos)
            if not s: break
            while 1:
                n = max(s.rfind('\r'), s.rfind('\n'))
                if n == -1:
                    buf = s + buf
                    break
                yield s[n:]+buf
                s = s[:n]
                buf = ''
        return


##  PSStackParser
##
class PSStackParser(PSBaseParser):

    def __init__(self, fp):
        PSBaseParser.__init__(self, fp)
        self.reset()
        return
    
    def reset(self):
        self.context = []
        self.curtype = None
        self.curstack = []
        self.results = []
        return

    def seek(self, pos):
        PSBaseParser.seek(self, pos)
        self.reset()
        return

    def push(self, *objs):
        self.curstack.extend(objs)
        return
    def pop(self, n):
        objs = self.curstack[-n:]
        self.curstack[-n:] = []
        return objs
    def popall(self):
        objs = self.curstack
        self.curstack = []
        return objs
    def add_results(self, *objs):
        self.results.extend(objs)
        return

    def start_type(self, pos, type):
        self.context.append((pos, self.curtype, self.curstack))
        (self.curtype, self.curstack) = (type, [])
        return
    def end_type(self, type):
        if self.curtype != type:
            raise PSTypeError('Type mismatch: %r != %r' % (self.curtype, type))
        objs = [ obj for (_,obj) in self.curstack ]
        (pos, self.curtype, self.curstack) = self.context.pop()
        return (pos, objs)

    def do_keyword(self, pos, token):
        return
    
    def nextobject(self, direct=False):
        '''
        Yields a list of objects: keywords, literals, strings, 
        numbers, arrays and dictionaries. Arrays and dictionaries
        are represented as Python sequence and dictionaries.
        '''
        while not self.results:
            (pos, token) = self.nexttoken()
            ##print (pos,token), (self.curtype, self.curstack)
            if (isinstance(token, int) or
                    isinstance(token, float) or
                    isinstance(token, bool) or
                    isinstance(token, str) or
                    isinstance(token, PSLiteral)):
                # normal token
                self.push((pos, token))
            elif token == KEYWORD_ARRAY_BEGIN:
                # begin array
                self.start_type(pos, 'a')
            elif token == KEYWORD_ARRAY_END:
                # end array
                try:
                    self.push(self.end_type('a'))
                except PSTypeError:
                    if STRICT: raise
            elif token == KEYWORD_DICT_BEGIN:
                # begin dictionary
                self.start_type(pos, 'd')
            elif token == KEYWORD_DICT_END:
                # end dictionary
                try:
                    (pos, objs) = self.end_type('d')
                    if len(objs) % 2 != 0:
                        raise PSSyntaxError(
                            'Invalid dictionary construct: %r' % objs)
                    d = dict((literal_name(k), v) \
                                 for (k,v) in choplist(2, objs))
                    self.push((pos, d))
                except PSTypeError:
                    if STRICT: raise
            else:
                self.do_keyword(pos, token)
            if self.context:
                continue
            else:
                if direct:
                    return self.pop(1)[0]
                self.flush()
        obj = self.results.pop(0)
        return obj


LITERAL_CRYPT = PSLiteralTable.intern('Crypt')
LITERALS_FLATE_DECODE = (PSLiteralTable.intern('FlateDecode'), PSLiteralTable.intern('Fl'))
LITERALS_LZW_DECODE = (PSLiteralTable.intern('LZWDecode'), PSLiteralTable.intern('LZW'))
LITERALS_ASCII85_DECODE = (PSLiteralTable.intern('ASCII85Decode'), PSLiteralTable.intern('A85'))


##  PDF Objects
##
class PDFObject(PSObject): pass

class PDFException(PSException): pass
class PDFTypeError(PDFException): pass
class PDFValueError(PDFException): pass
class PDFNotImplementedError(PSException): pass


##  PDFObjRef
##
class PDFObjRef(PDFObject):
    
    def __init__(self, doc, objid, genno):
        if objid == 0:
            if STRICT:
                raise PDFValueError('PDF object id cannot be 0.')
        self.doc = doc
        self.objid = objid
        self.genno = genno
        return

    def __repr__(self):
        return '<PDFObjRef:%d %d>' % (self.objid, self.genno)

    def resolve(self):
        return self.doc.getobj(self.objid)


# resolve
def resolve1(x):
    '''
    Resolve an object. If this is an array or dictionary,
    it may still contains some indirect objects inside.
    '''
    while isinstance(x, PDFObjRef):
        x = x.resolve()
    return x

def resolve_all(x):
    '''
    Recursively resolve X and all the internals.
    Make sure there is no indirect reference within the nested object.
    This procedure might be slow.
    '''
    while isinstance(x, PDFObjRef):
        x = x.resolve()
    if isinstance(x, list):
        x = [ resolve_all(v) for v in x ]
    elif isinstance(x, dict):
        for (k,v) in x.iteritems():
            x[k] = resolve_all(v)
    return x

def decipher_all(decipher, objid, genno, x):
    '''
    Recursively decipher X.
    '''
    if isinstance(x, str):
        return decipher(objid, genno, x)
    decf = lambda v: decipher_all(decipher, objid, genno, v)
    if isinstance(x, list):
        x = [decf(v) for v in x]
    elif isinstance(x, dict):
        x = dict((k, decf(v)) for (k, v) in x.iteritems())
    return x


# Type cheking
def int_value(x):
    x = resolve1(x)
    if not isinstance(x, int):
        if STRICT:
            raise PDFTypeError('Integer required: %r' % x)
        return 0
    return x

def float_value(x):
    x = resolve1(x)
    if not isinstance(x, float):
        if STRICT:
            raise PDFTypeError('Float required: %r' % x)
        return 0.0
    return x

def num_value(x):
    x = resolve1(x)
    if not (isinstance(x, int) or isinstance(x, float)):
        if STRICT:
            raise PDFTypeError('Int or Float required: %r' % x)
        return 0
    return x

def str_value(x):
    x = resolve1(x)
    if not isinstance(x, str):
        if STRICT:
            raise PDFTypeError('String required: %r' % x)
        return ''
    return x

def list_value(x):
    x = resolve1(x)
    if not (isinstance(x, list) or isinstance(x, tuple)):
        if STRICT:
            raise PDFTypeError('List required: %r' % x)
        return []
    return x

def dict_value(x):
    x = resolve1(x)
    if not isinstance(x, dict):
        if STRICT:
            raise PDFTypeError('Dict required: %r' % x)
        return {}
    return x

def stream_value(x):
    x = resolve1(x)
    if not isinstance(x, PDFStream):
        if STRICT:
            raise PDFTypeError('PDFStream required: %r' % x)
        return PDFStream({}, '')
    return x

# ascii85decode(data)
def ascii85decode(data):
  n = b = 0
  out = ''
  for c in data:
    if '!' <= c and c <= 'u':
      n += 1
      b = b*85+(ord(c)-33)
      if n == 5:
        out += struct.pack('>L',b)
        n = b = 0
    elif c == 'z':
      assert n == 0
      out += '\0\0\0\0'
    elif c == '~':
      if n:
        for _ in range(5-n):
          b = b*85+84
        out += struct.pack('>L',b)[:n-1]
      break
  return out


##  PDFStream type
class PDFStream(PDFObject):
    def __init__(self, dic, rawdata, decipher=None):
        length = int_value(dic.get('Length', 0))
        eol = rawdata[length:]
        # quick and dirty fix for false length attribute,
        # might not work if the pdf stream parser has a problem
        if decipher != None and decipher.__name__ == 'decrypt_aes':
            if (len(rawdata) % 16) != 0:
                cutdiv = len(rawdata) // 16
                rawdata = rawdata[:16*cutdiv]
        else:
            if eol in ('\r', '\n', '\r\n'):
                rawdata = rawdata[:length]
                
        self.dic = dic
        self.rawdata = rawdata
        self.decipher = decipher
        self.data = None
        self.decdata = None
        self.objid = None
        self.genno = None
        return

    def set_objid(self, objid, genno):
        self.objid = objid
        self.genno = genno
        return
    
    def __repr__(self):
        if self.rawdata:
            return '<PDFStream(%r): raw=%d, %r>' % \
                   (self.objid, len(self.rawdata), self.dic)
        else:
            return '<PDFStream(%r): data=%d, %r>' % \
                   (self.objid, len(self.data), self.dic)

    def decode(self):
        assert self.data is None and self.rawdata is not None
        data = self.rawdata
        if self.decipher:
            # Handle encryption
            data = self.decipher(self.objid, self.genno, data)
            if gen_xref_stm:
                self.decdata = data # keep decrypted data
        if 'Filter' not in self.dic:
            self.data = data
            self.rawdata = None
            ##print self.dict
            return
        filters = self.dic['Filter']
        if not isinstance(filters, list):
            filters = [ filters ]
        for f in filters:
            if f in LITERALS_FLATE_DECODE:
                # will get errors if the document is encrypted.
                data = zlib.decompress(data)
            elif f in LITERALS_LZW_DECODE:
                data = ''.join(LZWDecoder(StringIO(data)).run())
            elif f in LITERALS_ASCII85_DECODE:
                data = ascii85decode(data)
            elif f == LITERAL_CRYPT:
                raise PDFNotImplementedError('/Crypt filter is unsupported')
            else:
                raise PDFNotImplementedError('Unsupported filter: %r' % f)
            # apply predictors
            if 'DP' in self.dic:
                params = self.dic['DP']
            else:
                params = self.dic.get('DecodeParms', {})
            if 'Predictor' in params:
                pred = int_value(params['Predictor'])
                if pred:
                    if pred != 12:
                        raise PDFNotImplementedError(
                            'Unsupported predictor: %r' % pred)
                    if 'Columns' not in params:
                        raise PDFValueError(
                            'Columns undefined for predictor=12')
                    columns = int_value(params['Columns'])
                    buf = ''
                    ent0 = '\x00' * columns
                    for i in xrange(0, len(data), columns+1):
                        pred = data[i]
                        ent1 = data[i+1:i+1+columns]
                        if pred == '\x02':
                            ent1 = ''.join(chr((ord(a)+ord(b)) & 255) \
                                               for (a,b) in zip(ent0,ent1))
                        buf += ent1
                        ent0 = ent1
                    data = buf
        self.data = data
        self.rawdata = None
        return

    def get_data(self):
        if self.data is None:
            self.decode()
        return self.data

    def get_rawdata(self):
        return self.rawdata

    def get_decdata(self):
        if self.decdata is not None:
            return self.decdata
        data = self.rawdata
        if self.decipher and data:
            # Handle encryption
            data = self.decipher(self.objid, self.genno, data)
        return data

        
##  PDF Exceptions
##
class PDFSyntaxError(PDFException): pass
class PDFNoValidXRef(PDFSyntaxError): pass
class PDFEncryptionError(PDFException): pass
class PDFPasswordIncorrect(PDFEncryptionError): pass

# some predefined literals and keywords.
LITERAL_OBJSTM = PSLiteralTable.intern('ObjStm')
LITERAL_XREF = PSLiteralTable.intern('XRef')
LITERAL_PAGE = PSLiteralTable.intern('Page')
LITERAL_PAGES = PSLiteralTable.intern('Pages')
LITERAL_CATALOG = PSLiteralTable.intern('Catalog')


##  XRefs
##

##  PDFXRef
##
class PDFXRef(object):

    def __init__(self):
        self.offsets = None
        return

    def __repr__(self):
        return '<PDFXRef: objs=%d>' % len(self.offsets)

    def objids(self):
        return self.offsets.iterkeys()

    def load(self, parser):
        self.offsets = {}
        while 1:
            try:
                (pos, line) = parser.nextline()
            except PSEOF:
                raise PDFNoValidXRef('Unexpected EOF - file corrupted?')
            if not line:
                raise PDFNoValidXRef('Premature eof: %r' % parser)
            if line.startswith('trailer'):
                parser.seek(pos)
                break
            f = line.strip().split(' ')
            if len(f) != 2:
                raise PDFNoValidXRef('Trailer not found: %r: line=%r' % (parser, line))
            try:
                (start, nobjs) = map(int, f)
            except ValueError:
                raise PDFNoValidXRef('Invalid line: %r: line=%r' % (parser, line))
            for objid in xrange(start, start+nobjs):
                try:
                    (_, line) = parser.nextline()
                except PSEOF:
                    raise PDFNoValidXRef('Unexpected EOF - file corrupted?')
                f = line.strip().split(' ')
                if len(f) != 3:
                    raise PDFNoValidXRef('Invalid XRef format: %r, line=%r' % (parser, line))
                (pos, genno, use) = f
                if use != 'n': continue
                self.offsets[objid] = (int(genno), int(pos))
        self.load_trailer(parser)
        return
    
    KEYWORD_TRAILER = PSKeywordTable.intern('trailer')
    def load_trailer(self, parser):
        try:
            (_,kwd) = parser.nexttoken()
            assert kwd is self.KEYWORD_TRAILER
            (_,dic) = parser.nextobject(direct=True)
        except PSEOF:
            x = parser.pop(1)
            if not x:
                raise PDFNoValidXRef('Unexpected EOF - file corrupted')
            (_,dic) = x[0]
        self.trailer = dict_value(dic)
        return

    def getpos(self, objid):
        try:
            (genno, pos) = self.offsets[objid]
        except KeyError:
            raise
        return (None, pos)


##  PDFXRefStream
##
class PDFXRefStream(object):

    def __init__(self):
        self.index = None
        self.data = None
        self.entlen = None
        self.fl1 = self.fl2 = self.fl3 = None
        return

    def __repr__(self):
        return '<PDFXRef: objids=%s>' % self.index

    def objids(self):
        for first, size in self.index:
            for objid in xrange(first, first + size):
                yield objid
    
    def load(self, parser, debug=0):
        (_,objid) = parser.nexttoken() # ignored
        (_,genno) = parser.nexttoken() # ignored
        (_,kwd) = parser.nexttoken()
        (_,stream) = parser.nextobject()
        if not isinstance(stream, PDFStream) or \
           stream.dic['Type'] is not LITERAL_XREF:
            raise PDFNoValidXRef('Invalid PDF stream spec.')
        size = stream.dic['Size']
        index = stream.dic.get('Index', (0,size))
        self.index = zip(islice(index, 0, None, 2),
                         islice(index, 1, None, 2))
        (self.fl1, self.fl2, self.fl3) = stream.dic['W']
        self.data = stream.get_data()
        self.entlen = self.fl1+self.fl2+self.fl3
        self.trailer = stream.dic
        return
    
    def getpos(self, objid):
        offset = 0
        for first, size in self.index:
            if first <= objid  and objid < (first + size):
                break
            offset += size
        else:
            raise KeyError(objid)
        i = self.entlen * ((objid - first) + offset)
        ent = self.data[i:i+self.entlen]
        f1 = nunpack(ent[:self.fl1], 1)
        if f1 == 1:
            pos = nunpack(ent[self.fl1:self.fl1+self.fl2])
            genno = nunpack(ent[self.fl1+self.fl2:])
            return (None, pos)
        elif f1 == 2:
            objid = nunpack(ent[self.fl1:self.fl1+self.fl2])
            index = nunpack(ent[self.fl1+self.fl2:])
            return (objid, index)
        # this is a free object
        raise KeyError(objid)


##  PDFDocument
##
##  A PDFDocument object represents a PDF document.
##  Since a PDF file is usually pretty big, normally it is not loaded
##  at once. Rather it is parsed dynamically as processing goes.
##  A PDF parser is associated with the document.
##
class PDFDocument(object):

    def __init__(self):
        self.xrefs = []
        self.objs = {}
        self.parsed_objs = {}
        self.root = None
        self.catalog = None
        self.parser = None
        self.encryption = None
        self.decipher = None
        # dictionaries for fileopen
        self.fileopen = {}
        self.urlresult = {}        
        self.ready = False
        return

    # set_parser(parser)
    #   Associates the document with an (already initialized) parser object.
    def set_parser(self, parser):
        if self.parser: return
        self.parser = parser
        # The document is set to be temporarily ready during collecting
        # all the basic information about the document, e.g.
        # the header, the encryption information, and the access rights 
        # for the document.
        self.ready = True
        # Retrieve the information of each header that was appended
        # (maybe multiple times) at the end of the document.
        self.xrefs = parser.read_xref()
        for xref in self.xrefs:
            trailer = xref.trailer
            if not trailer: continue

            # If there's an encryption info, remember it.
            if 'Encrypt' in trailer:
                #assert not self.encryption
                try:
                    self.encryption = (list_value(trailer['ID']),
                                   dict_value(trailer['Encrypt']))
                # fix for bad files
                except:
                    self.encryption = ('ffffffffffffffffffffffffffffffffffff',
                                       dict_value(trailer['Encrypt']))
            if 'Root' in trailer:
                self.set_root(dict_value(trailer['Root']))
                break
        else:
            raise PDFSyntaxError('No /Root object! - Is this really a PDF?')
        # The document is set to be non-ready again, until all the
        # proper initialization (asking the password key and
        # verifying the access permission, so on) is finished.
        self.ready = False
        return

    # set_root(root)
    #   Set the Root dictionary of the document.
    #   Each PDF file must have exactly one /Root dictionary.
    def set_root(self, root):
        self.root = root
        self.catalog = dict_value(self.root)
        if self.catalog.get('Type') is not LITERAL_CATALOG:
            if STRICT:
                raise PDFSyntaxError('Catalog not found!')
        return
    # initialize(password='')
    #   Perform the initialization with a given password.
    #   This step is mandatory even if there's no password associated
    #   with the document.
    def initialize(self, password=''):
        if not self.encryption:
            self.is_printable = self.is_modifiable = self.is_extractable = True
            self.ready = True
            return
        (docid, param) = self.encryption
        type = literal_name(param['Filter'])
        if type == 'Adobe.APS':
            return self.initialize_adobe_ps(password, docid, param)
        if type == 'Standard':
            return self.initialize_standard(password, docid, param)
        if type == 'EBX_HANDLER':
            return self.initialize_ebx(password, docid, param)
        if type == 'FOPN_fLock':
            # remove of unnecessairy password attribute
            return self.initialize_fopn_flock(docid, param)  
        if type == 'FOPN_foweb':
            # remove of unnecessairy password attribute
            return self.initialize_fopn(docid, param)
        raise PDFEncryptionError('Unknown filter: param=%r' % param)

    def initialize_adobe_ps(self, password, docid, param):
        global KEYFILEPATH
        self.decrypt_key = self.genkey_adobe_ps(param)
        self.genkey = self.genkey_v4
        self.decipher = self.decrypt_aes
        self.ready = True
        return
    
    def getPrincipalKey(self, k=None, url=None, referer=None):
            if url == None:
                    url="ssl://edc.bibliothek-digital.de/edcws/services/urn:EDCLicenseService"
            data1='<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SO'+\
            'AP-ENV="http://s...content-available-to-author-only...p.org/soap/envelope/" xmlns:SOAP-ENC="http'+\
            '://schemas.xmlsoap.org/soap/encoding/" xmlns:xsi="http://w...content-available-to-author-only...3.org/2001/'+\
            'XMLSchema-instance" xmlns:xsd="http://w...content-available-to-author-only...3.org/2001/XMLSchema" xmlns:tns1="'+\
            'http://e...content-available-to-author-only...e.com/edcwebservice" xmlns:impl="http://localhost:8080/axis/s'+\
            'ervices/urn:EDCLicenseService" xmlns:ns2="http://c...content-available-to-author-only...e.com" xmlns:ns1="'+\
            'http://n...content-available-to-author-only...e.com/PolicyServer/ws"><SOAP-ENV:Header><EDCSecurity>&lt;wsse:Security '+\
            'xmlns:wsse="http://d...content-available-to-author-only...n.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-'+\
            '1.0.xsd"&gt;&lt;wsse:UsernameToken&gt;&lt;wsse:Username&gt;edc_anonymous&lt;/wsse:Username&'+\
            'gt;&lt;wsse:Password Type="http://d...content-available-to-author-only...n.org/wss/2004/01/oasis-200401-wss-username-'+\
            'token-profile-1.0#PasswordText"&gt;edc_anonymous&lt;/wsse:Password&gt;&lt;/wsse:UsernameToken&'+\
            'gt;&lt;/wsse:Security&gt;</EDCSecurity><Version>7</Version><Locale>de-de</Locale></SOAP-ENV:Header>'+\
            '<SOAP-ENV:Body><impl:synchronize><SynchronizationRequest><firstTime>1</firstTime><licenseSeqNum>0</'+\
            'licenseSeqNum><policySeqNum>1</policySeqNum><revocationSeqNum>0</revocationSeqNum><'+\
            'watermarkTemplateSeqNum>0</watermarkTemplateSeqNum></SynchronizationRequest></'+\
            'impl:synchronize></SOAP-ENV:Body></SOAP-ENV:Envelope>'
            if k not in url[:40]:
                return None
            #~ extract host and path:
            host=re.compile(r'[a-zA-Z]://([^/]+)/.+', re.I).search(url).group(1)
            urlpath=re.compile(r'[a-zA-Z]://[^/]+(/.+)', re.I).search(url).group(1)
            
            # open a socket connection on port 80

            conn = httplib.HTTPSConnection(host, 443)
            
            #~ Headers for request
            headers={"Accept": "*/*", "Host": host, "User-Agent": "Mozilla/3.0 (compatible; Acrobat EDC SOAP 1.0)",
                     "Content-Type": "text/xml; charset=utf-8", "Cache-Control": "no-cache", "SOAPAction": ""}
            
            # send data1 and headers
            try:
                    conn.request("POST", urlpath, data1, headers)
            except:
                    raise ADEPTError("Could not post request to '"+host+"'.")
            
            # read respose
            try:
                    response = conn.getresponse()
                    responsedata=response.read()
            except:
                    raise ADEPTError("Could not read response from '"+host+"'.")
            
            # close connection
            conn.close()
            
            try:
                    key=re.compile(r'PricipalKey"((?!<key>).)*<key[^>]*>(((?!</key>).)*)</key>', re.I).search(responsedata).group(2)
            
            except :
                    key=None
            return key

    def genkey_adobe_ps(self, param):
        # nice little offline principal keys dictionary
        principalkeys = { 'bibliothek-digital.de': 'Dzqx8McQUNd2CDzBVmtnweUxVWlqJTMqyYtiDIc4dZI='.decode('base64')}
        for k, v in principalkeys.iteritems():
            result = self.getPrincipalKey(k)
            #print result
            if result != None:
                principalkeys[k] = result.decode('base64')
            else:
                raise ADEPTError("No (Online) PrincipalKey found.")
                
        self.is_printable = self.is_modifiable = self.is_extractable = True
##        print 'keyvalue'
##        print len(keyvalue)
##        print keyvalue.encode('hex')
        length = int_value(param.get('Length', 0)) / 8
        edcdata = str_value(param.get('EDCData')).decode('base64')
        pdrllic = str_value(param.get('PDRLLic')).decode('base64')
        pdrlpol = str_value(param.get('PDRLPol')).decode('base64')          
        #print 'ecd rights'
        edclist = []
        for pair in edcdata.split('\n'):
            edclist.append(pair)
##        print edclist
##        print 'edcdata decrypted'
##        print edclist[0].decode('base64').encode('hex')
##        print edclist[1].decode('base64').encode('hex')
##        print edclist[2].decode('base64').encode('hex')
##        print edclist[3].decode('base64').encode('hex')
##        print 'offlinekey'
##        print len(edclist[9].decode('base64'))
##        print pdrllic
        # principal key request
        for key in principalkeys:
            if key in pdrllic:
                principalkey = principalkeys[key]
            else:
                raise ADEPTError('Cannot find principal key for this pdf')
##        print 'minorversion'
##        print int(edclist[8])
        # fix for minor version
##        minorversion = int(edclist[8]) - 100
##        if minorversion < 1:
##            minorversion = 1
##        print int(minorversion)
        shakey = SHA256.new()
        shakey.update(principalkey)
##        for i in range(0,minorversion):
##            shakey.update(principalkey)
        shakey = shakey.digest()
##        shakey = SHA256.new(principalkey).digest()
        ivector = 16 * chr(0)
        #print shakey
        plaintext = AES.new(shakey,AES.MODE_CBC,ivector).decrypt(edclist[9].decode('base64'))
        if plaintext[-16:] != 16 * chr(16):
            raise ADEPTError('Offlinekey cannot be decrypted, aborting (hint: redownload pdf) ...')
        pdrlpol = AES.new(plaintext[16:32],AES.MODE_CBC,edclist[2].decode('base64')).decrypt(pdrlpol)
        if ord(pdrlpol[-1]) < 1 or ord(pdrlpol[-1]) > 16:
            raise ADEPTError('Could not decrypt PDRLPol, aborting ...')
        else:
            cutter = -1 * ord(pdrlpol[-1])
            #print cutter
            pdrlpol = pdrlpol[:cutter]            
        #print plaintext.encode('hex')
        #print 'pdrlpol'
        #print pdrlpol
        return plaintext[:16]
    
    PASSWORD_PADDING = '(\xbfN^Nu\x8aAd\x00NV\xff\xfa\x01\x08..' \
                       '\x00\xb6\xd0h>\x80/\x0c\xa9\xfedSiz'
    # experimental aes pw support
    def initialize_standard(self, password, docid, param):
        # copy from a global variable
        V = int_value(param.get('V', 0))
        if (V <=0 or V > 4):
            raise PDFEncryptionError('Unknown algorithm: param=%r' % param)
        length = int_value(param.get('Length', 40)) # Key length (bits)
        O = str_value(param['O'])
        R = int_value(param['R']) # Revision
        if 5 <= R:
            raise PDFEncryptionError('Unknown revision: %r' % R)
        U = str_value(param['U'])
        P = int_value(param['P'])
        try:
            EncMetadata = str_value(param['EncryptMetadata'])
        except:
            EncMetadata = 'True'
        self.is_printable = bool(P & 4)        
        self.is_modifiable = bool(P & 8)
        self.is_extractable = bool(P & 16)
        self.is_annotationable = bool(P & 32)
        self.is_formsenabled = bool(P & 256)
        self.is_textextractable = bool(P & 512)
        self.is_assemblable = bool(P & 1024)
        self.is_formprintable = bool(P & 2048) 
        # Algorithm 3.2
        password = (password+self.PASSWORD_PADDING)[:32] # 1
        hash = hashlib.md5(password) # 2
        hash.update(O) # 3
        hash.update(struct.pack('<l', P)) # 4
        hash.update(docid[0]) # 5
        # aes special handling if metadata isn't encrypted
        if EncMetadata == ('False' or 'false'):
            hash.update('ffffffff'.decode('hex'))
            # 6
##            raise PDFNotImplementedError(
##                'Revision 4 encryption is currently unsupported')
        if 5 <= R:
            # 8
            for _ in xrange(50):
                hash = hashlib.md5(hash.digest()[:length/8])
        key = hash.digest()[:length/8]
        if R == 2:
            # Algorithm 3.4
            u1 = ARC4.new(key).decrypt(password)
        elif R >= 3:
            # Algorithm 3.5
            hash = hashlib.md5(self.PASSWORD_PADDING) # 2
            hash.update(docid[0]) # 3
            x = ARC4.new(key).decrypt(hash.digest()[:16]) # 4
            for i in xrange(1,19+1):
                k = ''.join( chr(ord(c) ^ i) for c in key )
                x = ARC4.new(k).decrypt(x)
            u1 = x+x # 32bytes total
        if R == 2:
            is_authenticated = (u1 == U)
        else:
            is_authenticated = (u1[:16] == U[:16])
        if not is_authenticated:
            raise ADEPTError('Password is not correct.')
##            raise PDFPasswordIncorrect
        self.decrypt_key = key
        # genkey method
        if V == 1 or V == 2:
            self.genkey = self.genkey_v2
        elif V == 3:
            self.genkey = self.genkey_v3
        elif V == 4:
            self.genkey = self.genkey_v2
         #self.genkey = self.genkey_v3 if V == 3 else self.genkey_v2
        # rc4
        if V != 4:
            self.decipher = self.decipher_rc4  # XXX may be AES
        # aes
        elif V == 4 and Length == 128:
            elf.decipher = self.decipher_aes
        elif V == 4 and Length == 256:
            raise PDFNotImplementedError('AES256 encryption is currently unsupported')
        self.ready = True
        return

    def initialize_ebx(self, password, docid, param):
        global KEYFILEPATH
        self.is_printable = self.is_modifiable = self.is_extractable = True
        # keyfile path is wrong
        if KEYFILEPATH == False:
            errortext = 'Cannot find adeptkey.der keyfile. Use ineptkey to generate it.'
            raise ADEPTError(errortext)
        with open(password, 'rb') as f:
            keyder = f.read()
        #    KEYFILEPATH = ''
        key = ASN1Parser([ord(x) for x in keyder])
        key = [bytesToNumber(key.getChild(x).value) for x in xrange(1, 4)]
        rsa = RSA.construct(key)
        length = int_value(param.get('Length', 0)) / 8
        rights = str_value(param.get('ADEPT_LICENSE')).decode('base64')
        rights = zlib.decompress(rights, -15)
        rights = etree.fromstring(rights)
        expr = './/{http://n...content-available-to-author-only...e.com/adept}encryptedKey'
        bookkey = ''.join(rights.findtext(expr)).decode('base64')
        bookkey = rsa.decrypt(bookkey)
        if bookkey[0] != '\x02':
            raise ADEPTError('error decrypting book session key')
        index = bookkey.index('\0') + 1
        bookkey = bookkey[index:]
        ebx_V = int_value(param.get('V', 4))
        ebx_type = int_value(param.get('EBX_ENCRYPTIONTYPE', 6))
        # added because of the booktype / decryption book session key error
        if ebx_V == 3:
            V = 3        
        elif ebx_V < 4 or ebx_type < 6:
            V = ord(bookkey[0])
            bookkey = bookkey[1:]
        else:
            V = 2
        if length and len(bookkey) != length:
            raise ADEPTError('error decrypting book session key')
        self.decrypt_key = bookkey
        self.genkey = self.genkey_v3 if V == 3 else self.genkey_v2
        self.decipher = self.decrypt_rc4
        self.ready = True
        return

    # fileopen support    
    def initialize_fopn_flock(self, docid, param):
        raise ADEPTError('FOPN_fLock not supported, yet ...')
        # debug mode processing
        global DEBUG_MODE
        global IVERSION
        if DEBUG_MODE == True:
            if os.access('.',os.W_OK) == True:
                debugfile = open('ineptpdf-'+IVERSION+'-debug.txt','w')
            else:
                raise ADEPTError('Cannot write debug file, current directory is not writable')
        self.is_printable = self.is_modifiable = self.is_extractable = True
        # get parameters and add it to the fo dictionary
        self.fileopen['V'] = int_value(param.get('V',2))        
        # crypt base
        (docid, param) = self.encryption
        #rights = dict_value(param['Info'])
        rights = param['Info']        
        #print rights
        if DEBUG_MODE == True: debugfile.write(rights + '\n\n')
##        for pair in rights.split(';'):
##            try:
##                key, value = pair.split('=',1)
##                self.fileopen[key] = value
##            # fix for some misconfigured INFO variables
##            except:
##                pass
##        kattr = { 'SVID': 'ServiceID', 'DUID': 'DocumentID', 'I3ID': 'Ident3ID', \
##                  'I4ID': 'Ident4ID', 'VERS': 'EncrVer', 'PRID': 'USR'}
##        for keys in  kattr:
##            try:
##                self.fileopen[kattr[keys]] = self.fileopen[keys]
##                del self.fileopen[keys]
##            except:
##                continue
        # differentiate OS types
##        sysplatform = sys.platform
##        # if ostype is Windows
##        if sysplatform=='win32':
##            self.osuseragent = 'Windows NT 6.0'
##            self.get_macaddress = self.get_win_macaddress
##            self.fo_sethwids = self.fo_win_sethwids
##            self.BrowserCookie = WinBrowserCookie
##        elif sysplatform=='linux2':
##            adeptout = 'Linux is not supported, yet.\n'
##            raise ADEPTError(adeptout)
##            self.osuseragent = 'Linux i686'
##            self.get_macaddress = self.get_linux_macaddress            
##            self.fo_sethwids = self.fo_linux_sethwids            
##        else:
##            adeptout = ''
##            adeptout = adeptout + 'Due to various privacy violations from Apple\n'
##            adeptout = adeptout + 'Mac OS X support is disabled by default.'
##            raise ADEPTError(adeptout)            
##        # add static arguments for http/https request
##        self.fo_setattributes()
##        # add hardware specific arguments for http/https request        
##        self.fo_sethwids()
##
##        if 'Code' in self.urlresult:            
##            if self.fileopen['Length'] == len(self.urlresult['Code']):
##                self.decrypt_key = self.urlresult['Code']
##            else:
##                self.decrypt_key = self.urlresult['Code'].decode('hex')
##        else:
##            raise ADEPTError('Cannot find decryption key.')
        self.decrypt_key = 'stuff'
        self.genkey = self.genkey_v2
        self.decipher = self.decrypt_rc4
        self.ready = True
        return

    def initialize_fopn(self, docid, param):
        # debug mode processing
        global DEBUG_MODE
        global IVERSION
        if DEBUG_MODE == True:
            if os.access('.',os.W_OK) == True:
                debugfile = open('ineptpdf-'+IVERSION+'-debug.txt','w')
            else:
                raise ADEPTError('Cannot write debug file, current directory is not writable')
        self.is_printable = self.is_modifiable = self.is_extractable = True
        # get parameters and add it to the fo dictionary
        self.fileopen['Length'] = int_value(param.get('Length', 0)) / 8
        self.fileopen['VEID'] = str_value(param.get('VEID'))
        self.fileopen['BUILD'] = str_value(param.get('BUILD'))
        self.fileopen['SVID'] = str_value(param.get('SVID'))
        self.fileopen['DUID'] = str_value(param.get('DUID'))
        self.fileopen['V'] = int_value(param.get('V',2))        
        # crypt base
        rights = str_value(param.get('INFO')).decode('base64')
        rights = self.genkey_fileopeninfo(rights)
        if DEBUG_MODE == True: debugfile.write(rights + '\n\n')    
        for pair in rights.split(';'):
            try:
                key, value = pair.split('=',1)
                self.fileopen[key] = value
            # fix for some misconfigured INFO variables
            except:
                pass
        kattr = { 'SVID': 'ServiceID', 'DUID': 'DocumentID', 'I3ID': 'Ident3ID', \
                  'I4ID': 'Ident4ID', 'VERS': 'EncrVer', 'PRID': 'USR'}
        for keys in  kattr:
            # fishing some misconfigured slashs out of it
            try:
                self.fileopen[kattr[keys]] = urllib.quote(self.fileopen[keys],safe='')
                del self.fileopen[keys]
            except:
                continue
        # differentiate OS types
        sysplatform = sys.platform
        # if ostype is Windows
        if sysplatform=='win32':
            self.osuseragent = 'Windows NT 6.0'
            self.get_macaddress = self.get_win_macaddress
            self.fo_sethwids = self.fo_win_sethwids
            self.BrowserCookie = WinBrowserCookie
        elif sysplatform=='linux2' or sysplatform=='linux3':
	    import fcntl
	    import struct
            self.osuseragent = 'Linux i686'
            self.get_macaddress =  self.get_linux_macaddress
            self.fo_sethwids = self.fo_linux_sethwids     
            self.BrowserCookie = LinBrowserCookie       
        else:
            adeptout = ''
            adeptout = adeptout + 'Mac OS X is not supported, yet.' 
            adeptout = adeptout + 'Read the blogs FAQs for more information'
            raise ADEPTError(adeptout)            
        # add static arguments for http/https request
        self.fo_setattributes()
        # add hardware specific arguments for http/https request        
        self.fo_sethwids()
        #if DEBUG_MODE == True: debugfile.write(self.fileopen)
        if 'UURL' in self.fileopen:
            buildurl = self.fileopen['UURL']
        else:
            buildurl = self.fileopen['PURL']
        # fix for bad DPRM structure
        if self.fileopen['DPRM'][0] != r'/':
            self.fileopen['DPRM'] = r'/' + self.fileopen['DPRM']
        # genius fix for bad server urls (IMHO)
        if '?' in self.fileopen['DPRM']:
            buildurl = buildurl + self.fileopen['DPRM'] + '&'
        else:
            buildurl = buildurl + self.fileopen['DPRM'] + '?'            

        # debug customization
        #self.fileopen['Machine'] = ''
        #self.fileopen['Disk'] = ''


        surl = ( 'Stamp', 'Mode', 'USR', 'ServiceID', 'DocumentID',\
                 'Ident3ID', 'Ident4ID','DocStrFmt', 'OSType', 'OSName', 'OSData', 'Language',\
                 'LngLCID', 'LngRFC1766', 'LngISO4Char', 'Build', 'ProdVer', 'EncrVer',\
                 'Machine', 'Disk', 'Uuid', 'PrevMach', 'PrevDisk',\
                 'FormHFT',\
                 'SelServer', 'AcroVersion', 'AcroProduct', 'AcroReader',\
                 'AcroCanEdit', 'AcroPrefIDib', 'InBrowser', 'CliAppName',\
                 'DocIsLocal', 'DocPathUrl', 'VolName', 'VolType', 'VolSN',\
                 'FSName',  'FowpKbd', 'OSBuild',\
                  'RequestSchema')
        
        #settings request and special modes
        if 'EVER' in self.fileopen and float(self.fileopen['EVER']) < 3.8:
            self.fileopen['Mode'] = 'ICx'
       
        origurl = buildurl
        buildurl = buildurl + 'Request=Setting'        
        for keys in surl:
            try:
                buildurl = buildurl + '&' + keys + '=' + self.fileopen[keys]
            except:
                continue
        if DEBUG_MODE == True: debugfile.write( 'settings url:\n')
        if DEBUG_MODE == True: debugfile.write( buildurl+'\n\n')
        # custom user agent identification?
        if 'AGEN' in self.fileopen:
            useragent = self.fileopen['AGEN']
            urllib.URLopener.version = useragent
        # attribute doesn't exist - take the default user agent
        else:
            urllib.URLopener.version = self.osuseragent
        # try to open the url
        try:
            u = urllib.urlopen(buildurl)
            u.geturl()
            result = u.read()
        except:
            raise ADEPTError('No internet connection or a blocking firewall!')
##        finally:
##            u.close()
        # getting rid of the line feed
        if DEBUG_MODE == True: debugfile.write('Settings'+'\n')
        if DEBUG_MODE == True: debugfile.write(result+'\n\n')
        #get rid of unnecessary characters
        result = result.rstrip('\n')
        result = result.rstrip(chr(13))
        result = result.lstrip('\n')
        result = result.lstrip(chr(13)) 
        self.surlresult = {}
        for pair in result.split('&'):
            try:
                key, value = pair.split('=',1)
                # fix for bad server response
                if key not in self.surlresult:
                    self.surlresult[key] = value
            except:
                pass
        if 'RequestSchema' in self.surlresult:
            self.fileopen['RequestSchema'] = self.surlresult['RequestSchema']
        if 'ServerSessionData' in self.surlresult:
            self.fileopen['ServerSessionData'] = self.surlresult['ServerSessionData']
        if 'SetScope' in self.surlresult:
            self.fileopen['RequestSchema'] = self.surlresult['SetScope']            
        #print self.surlresult
        if 'RetVal' in self.surlresult and 'SEMO' not in self.fileopen and(('Reason' in self.surlresult and \
           self.surlresult['Reason'] == 'AskUnp') or ('SetTarget' in self.surlresult and\
                                               self.surlresult['SetTarget'] == 'UnpDlg')):
            # get user and password dialog
            try:
                self.gen_pw_dialog(self.surlresult['UnpUiName'], self.surlresult['UnpUiPass'],\
                                   self.surlresult['UnpUiTitle'], self.surlresult['UnpUiOk'],\
                                   self.surlresult['UnpUiSunk'], self.surlresult['UnpUiComm'])
            except:
                self.gen_pw_dialog()
            
        # the fileopen check might not be always right because of strange server responses    
        if 'SEMO' in self.fileopen and (self.fileopen['SEMO'] == '1'\
            or self.fileopen['SEMO'] == '2') and ('CSES' in self.fileopen and\
                                                  self.fileopen['CSES'] != 'fileopen'):
            # get the url name for the cookie(s)
            if 'CURL' in self.fileopen:
                self.surl = self.fileopen['CURL']
            if 'CSES' in self.fileopen:
                self.cses = self.fileopen['CSES']
            elif 'PHOS' in self.fileopen:
                self.surl = self.fileopen['PHOS']
            elif 'LHOS' in self.fileopen:
                self.surl = self.fileopen['LHOS']
            else:
                raise ADEPTError('unknown Cookie name.\n Check ineptpdf forum for further assistance')
            self.pwfieldreq = 1
            # session cookie processing
            if self.fileopen['SEMO'] == '1':
                cookies = self.BrowserCookie()
                #print self.cses
                #print self.surl
       
