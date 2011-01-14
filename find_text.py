#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# find_text - a simple text finder written in Python
#
# This program is designed to extract text files from binary dumps. It was written
# to extract text data from file-system dumps. I wrote it because tools like scalpel
# and foremost while great for extracting structured data with headers and footers kinda
# sucks for plain text.
#
# The sequence is simple:
#   1. start at block 0
#   2. are the bytes ASCII text
#     - no skip to next block, start again
#     - yes continue until
#       - start getting zeros (end of block)
#       - start getting gibberish (throw away goto next block) 
#
# (C) Alex Bennée
# Available under GPLv3
#

import os
import getopt,sys
import re

# A good basic block size which matches most underlying disk hardware
# This can be specified to larger number to align with file-system blocks
blocksize=512

# Shall we be verbose?
verbose=False

# Regex objects
all_text=re.compile("[\s\x20-\x7e]{512}")
terminated_text=re.compile("[\s\x20-\x7e]{1,511}\x00")

# Match text, if set the existence of this in recovered text will cause it to dump
match_text=[]
# nomatch text, if set the existence of this in recovered text will cause it not to dump
nomatch_text=[]

# Heuristic, minimum number of words for 'valid' text
min_words=20

# Save recovered files, file mask and count
save=False
recover_name="ft"
recover_count=0

def save_recovered_text(text):
    """
    Save text out to a file on the disk
    """
    if save:
        global recover_count
    
        outfn = "%s_%08d" % (recover_name, recover_count)
        print "writing %s" % (outfn)
        if os.path.exists(outfn):
            print "Not going to overwrite existing data: %s" % (outfn)
            exit(-1)
        else:
            f = open(outfn, "w")
            f.write(text)
            f.close()
            
        recover_count += 1
    else:
        print "Found text block:\n%s\nEND" % (text)
        
    return

def check_for_match(text, word_list):
    """
    Check to see if text contains anything in word_list
    """
    if len(word_list) > 0:
        for m in word_list:
            if text.find(m) >= 0:
                return True
            
    return False


def handle_recovered_text(text):
    """
    Do some heuristics on the recovered text and decide
    if we want to dump it out.
    """
    #if verbose: print "handle_recovered_text: checking:\n%s\n" % (text)
    
    if len(match_text) > 0:
        if check_for_match(text, nomatch_text):
            # found nomatch phrase
            return

        if not check_for_match(text, match_text):
            # didn't find match phrase
            return

        # didn't find nomatch_text and found match_text
        save_recovered_text(text)
    elif len(nomatch_text) > 0:
        if check_for_match(text, nomatch_text):
            # found nomatch phrase
            return

        # didn't find nomatch_text
        save_recovered_text(text)
    else:
        words = text.split()
        if len(words)>min_words:
            save_recovered_text(text)
    

def process_dump_block(f, pos):
    #if verbose: print "process_dump_block, position = %d" % (pos)
    
    f.seek(pos)
    bytes = 0
    done = False
    recovered = ""
    
    while not done:
        data = f.read(blocksize)
        bytes = bytes + blocksize

        m = all_text.match(data)
        if m:
            recovered += data
        else:
            m = terminated_text.match(data)
            if m:
                recovered += data[m.start():m.end()-1]
            done = True

    # if we recovered any text we should print it
    if len(recovered)>0:
        handle_recovered_text(recovered)

    #if verbose: print "process_dump_block done after %d bytes" % (bytes)
    return bytes

def process_dump_file(filename):
    if verbose: print "process_dump_file: checking %s" % (filename)

    stat = os.stat(filename)
    done = False
    p = 0
    f = open(filename, "r")

    while not done:
        bytes = process_dump_block(f, p)
        p = p + bytes
        if p > stat.st_size:
            done = True

    if verbose: print "process_dump_file: done with %s" % (filename)

def usage():
    print "%s [-v] [FILE1 [FILE2 [..]]]" % (sys.argv[0])
    print """
    -h, --help            : this help message
    -v, --verbose         : verbose output
    -m, --match="string"  : treat a recovered hunk as valid if it contains this string
    -n, --nomatch="string" : treat a recovered hunk as invalid if it contains this string
    -s, --save            : save found hunks
"""

    sys.exit(1)

if __name__ == "__main__":
    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:], "hvm:n:s", ["help", "verbose", "match=", "nomatch=", "save"])
    except getopt.GetoptError, err:
        usage()

    for o,a in opts:
        if o in ("-h", "--help"):
            usage()
        if o in ("-v", "--verbose"):
            verbose=True
        if o in ("-m", "--magic"):
            match_text.append(a)
        if o in ("-n", "--nomatch"):
            nomatch_text.append(a)
        if o in ("-s", "--save"):
            save=True

    for arg in args:
        process_dump_file(arg)
