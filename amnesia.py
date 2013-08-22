# ////////////////////////////////////////////////////////////////////////////
# ----------------------------------------------------------------------------
#
# Amnesia - Layer 1 binary analysis system.
# Copyright (c) 2013 Tristan Strathearn (r3oath@gmail.com)
# Website: www.r3oath.com
#
# ----------------------------------------------------------------------------
# ////////////////////////////////////////////////////////////////////////////

import sys
import re
import pefile
import peutils
import pydasm
import struct

# ----------------------------------------------------------------------------

print """
          _____    __    __    __   __    _____  ______   __    _____
         /\___/\  /_/\  /\_\  /_/\ /\_\ /\_____\/ ____/\ /\_\  /\___/\\
        / / _ \ \ ) ) \/ ( (  ) ) \ ( (( (_____/) ) __\/ \/_/ / / _ \ \\
        \ \(_)/ //_/ \  / \_\/_/   \ \_\\\\ \__\   \ \ \    /\_\\\\ \(_)/ /
        / / _ \ \\\\ \ \\\\// / /\ \ \   / // /__/_  _\ \ \  / / // / _ \ \\
       ( (_( )_) ))_) )( (_(  )_) \ (_(( (_____\)____) )( (_(( (_( )_) )
        \/_/ \_\/ \_\/  \/_/  \_\/ \/_/ \/_____/\____\/  \/_/ \/_/ \_\/

                        Layer 1 binary analysis system.
                 Created by Tristan Strathearn (www.r3oath.com)
"""

# ----------------------------------------------------------------------------

def getInput(question, default_answer='', override=False):
    required = True if default_answer == '' else False

    if default_answer == '':
        formatted_string = '%s: ' % question
    else:
        formatted_string = '%s [%s]: ' % (question, default_answer)

    if override is True:
        formatted_string = '%s ' % question
        required = False

    while True:
        input_ = raw_input(formatted_string).strip()
        len_ = len(input_)
        if len_ > 0: return input_
        elif len_ == 0 and not required: return default_answer

def print_(message):
    print '%s' % message

def reportError(message):
    print_('ERROR: %s!' % message)

def spacer():
    print_('')

def drawLine():
    sys.stdout.write('>' * 80)

def getDataDump(file_):
    f = open(file_, 'rb')
    data = f.read()
    f.close()
    return data

# ----------------------------------------------------------------------------

# Hehe.
class ChocolateLog:
    log = []
    def __init__(self):
        self.log = []

    def add(self, message):
        self.log.append(message)

    def writeToFile(self):
        file_ = getInput('Please specify a file name')
        try:
            f = open(file_, 'w')
            for entry in self.log:
                f.write('%s\n' % entry)
            f.close()
        except:
            reportError('ChocolateLog failed to write to "%s"' % file_)

    def interactiveOutput(self):
        choice = getInput('Save to file instead of viewing?', 'N').upper()
        if choice.count('Y') > 0:
            self.writeToFile()
            return

        print_('Press Enter to scroll down, (S)ave or (Q)uit.')
        spacer()

        base = 0
        step_size = 20

        while True:
            index = 0
            for entry in self.log[base:]:
                print_(entry)
                index += 1
                if index >= step_size:
                    break

            base += index
            index = 0
            if base >= len(self.log):
                break

            choice = getInput('...',
                override=True).upper()

            if choice.count('Q') > 0:
                return
            elif choice.count('S') > 0:
                self.writeToFile()
                return
            else:
                continue

# ----------------------------------------------------------------------------

SUBJECT = None
ORIG_FILE = None
def loadSubject():
    global SUBJECT
    global ORIG_FILE

    ORIG_FILE = getInput('Please enter the file to process')
    try:
        SUBJECT = pefile.PE(ORIG_FILE)
        print_('Loaded the binary "%s"' % ORIG_FILE)
    except:
        reportError('Cannot open the file "%s"' % ORIG_FILE)
        loadSubject()
loadSubject()

# ----------------------------------------------------------------------------

def strings_display_all():
    try:
        min_ = int(getInput('Minimum string length', '5'))
        max_ = int(getInput('Maximum string length', '999'))
    except ValueError:
        reportError('Please specify only numeric values')
        return
    clog = ChocolateLog()
    clog.add('Strings:')
    data = getDataDump(ORIG_FILE)
    search_str = '[\x20-\x7F]{%i,%i}' % (min_, max_)
    for string_ in re.findall(search_str, data):
        string_ = string_.strip()
        if len(string_) > 0:
            clog.add('\t%s' % string_)
    clog.interactiveOutput()

def strings_search():
    try:
        min_ = int(getInput('Minimum string length', '5'))
        max_ = int(getInput('Maximum string length', '999'))
    except ValueError:
        reportError('Please specify only numeric values')
        return
    keyword = getInput('Keyword to search for').lower()
    clog = ChocolateLog()
    clog.add('Strings containing the keyword "%s":' % keyword)
    data = getDataDump(ORIG_FILE)
    search_str = '[\x20-\x7F]{%i,%i}' % (min_, max_)
    for string_ in re.findall(search_str, data):
        string_ = string_.strip()
        if string_.lower().count(keyword) > 0:
            clog.add('\t%s' % string_)
    clog.interactiveOutput()

def misc_verify_checksum():
    verified = SUBJECT.verify_checksum()
    if verified: print_('Checksum is valid.')
    else: print_('Checksum is invalid.')

def misc_generate_checksum():
    print_('Checksum: 0x%08X' % SUBJECT.generate_checksum())

def imports_dump_all():
    clog = ChocolateLog()
    clog.add('Imports:')
    for desc in SUBJECT.DIRECTORY_ENTRY_IMPORT:
        clog.add('\t%s' % desc.dll)
        for import_ in desc.imports:
            if import_.import_by_ordinal is not True:
                clog.add('\t\t%s' % import_.name)
            else:
                clog.add('\t\tOrdinal: %i' % import_.ordinal)
    clog.add('Delayed Imports:')
    for desc in SUBJECT.DIRECTORY_ENTRY_DELAY_IMPORT:
        clog.add('\t%s' % desc.dll)
        for import_ in desc.imports:
            if import_.import_by_ordinal is not True:
                clog.add('\t\t%s' % import_.name)
            else:
                clog.add('\t\tOrdinal: %i' % import_.ordinal)
    clog.interactiveOutput()

def imports_search():
    keyword = getInput('Keyword to search for').lower()
    clog = ChocolateLog()
    clog.add('Imports containing the keyword "%s":' % keyword)
    for desc in SUBJECT.DIRECTORY_ENTRY_IMPORT:
        for import_ in desc.imports:
            if import_.import_by_ordinal is not True:
                if import_.name.lower().count(keyword) > 0:
                    clog.add('\t%s (%s)' % (import_.name, desc.dll))
    for desc in SUBJECT.DIRECTORY_ENTRY_DELAY_IMPORT:
        for import_ in desc.imports:
            if import_.import_by_ordinal is not True:
                if import_.name.lower().count(keyword) > 0:
                    clog.add('\t%s (%s)' % (import_.name, desc.dll))
    clog.interactiveOutput()

def exports_dump_all():
    try:
        clog = ChocolateLog()
        clog.add('Exports:')
        for symbol in SUBJECT.DIRECTORY_ENTRY_EXPORT.symbols:
            if symbol.name is not None:
                if symbol.forwarder is None:
                    clog.add('\tOrdinal: %i / %s' %
                        (symbol.ordinal, symbol.name))
                else:
                    clog.add('\t%s -> %s' %
                        (symbol.name, symbol.forwarder))
            else:
                if symbol.forwarder is None:
                    clog.add('\tOrdinal: %i / %s' %
                        (symbol.ordinal, '<Exported by ordinal>'))
                else:
                    clog.add('\tOrdinal %i -> %s' %
                        (symbol.ordinal, symbol.forwarder))
        clog.interactiveOutput()
    except:
        print_('Could not be processed (binary may not export anything)')

def exports_search():
    try:
        keyword = getInput('Keyword to search for').lower()
        clog = ChocolateLog()
        clog.add('Exports containing the keyword "%s":' % keyword)
        for symbol in SUBJECT.DIRECTORY_ENTRY_EXPORT.symbols:
            if symbol.name is None:
                continue
            if symbol.name.lower().count(keyword) == 0:
                continue

            if symbol.name is not None:
                if symbol.forwarder is None:
                    clog.add('\tOrdinal: %i / %s' %
                        (symbol.ordinal, symbol.name))
                else:
                    clog.add('\t%s -> %s' %
                        (symbol.name, symbol.forwarder))
            else:
                if symbol.forwarder is None:
                    clog.add('\tOrdinal: %i / %s' %
                        (symbol.ordinal, '<Exported by ordinal>'))
                else:
                    clog.add('\tOrdinal %i -> %s' %
                        (symbol.ordinal, symbol.forwarder))
        clog.interactiveOutput()
    except:
        print_('Could not be processed (binary may not export anything)')

def exports_build_vs_pragma_forwards():
    s_by_name = '#pragma comment(linker, "/export:%s=%s.%s")\n'
    s_by_ord = '#pragma comment(linker, "/export:ord%i=%s.#%i,@%i,NONAME")\n'
    try:
        new_dll = getInput('DLL name to forward too').lower().strip('.dll')
        clog = ChocolateLog()
        for symbol in SUBJECT.DIRECTORY_ENTRY_EXPORT.symbols:
            if symbol.name is not None:
                clog.add(s_by_name % (symbol.name, new_dll, symbol.name))
            else:
                clog.add(s_by_ord %
                    (symbol.ordinal, new_dll, symbol.ordinal, symbol.ordinal))
        clog.interactiveOutput()
    except:
        print_('Could not be processed (binary may not export anything)')

def __assembly_offset(offset):
    return '%08X' % offset

def assembly_disassemble():
    try:
        max_bytes = int(getInput('Number of bytes to disassemble'))
    except ValueError:
        reportError('Please specify only numeric values')
        return
    clog = ChocolateLog()

    OEP = SUBJECT.OPTIONAL_HEADER.AddressOfEntryPoint
    OEP_base = OEP + SUBJECT.OPTIONAL_HEADER.ImageBase

    data = SUBJECT.get_memory_mapped_image()[OEP:]

    offset = 0
    while offset < max_bytes:
        ins = pydasm.get_instruction(data[offset:], pydasm.MODE_32)

        if ins is None:
            asm = 'db %02x' % ord(data[offset])
            clog.add('%s\t%s' % (__assembly_offset(offset), asm))
            offset += 1
            continue

        asm = pydasm.get_instruction_string(ins, pydasm.FORMAT_INTEL,
            OEP_base + offset)
        clog.add('%s\t%s' % (__assembly_offset(offset), asm))

        offset += ins.length

    clog.interactiveOutput()

def metadata_subject_overview():
    if SUBJECT.is_exe() is True:
        print_('Binary "%s" is an EXE' % ORIG_FILE)
    if SUBJECT.is_dll() is True:
        print_('Binary "%s" is a DLL' % ORIG_FILE)

    flagged = False
    if peutils.is_probably_packed(SUBJECT) is True:
        print_('Binary is possibly packed!')
        flagged = True
    if peutils.is_suspicious(SUBJECT) is True:
        print_('Binary is suspicious!')
        flagged = True

    if flagged is False:
        print_('Binary appears to be normal')

    print_('Address of Entry Point: 0x%08x' %
        SUBJECT.OPTIONAL_HEADER.AddressOfEntryPoint)

    misc_generate_checksum()
    misc_verify_checksum()

    print_('Sections:')
    for section in SUBJECT.sections:
        print_('\tRVA: 0x%08x - Name: %s - %i bytes' %
            (section.VirtualAddress, section.Name.strip('\x00'),
                section.SizeOfRawData))
    print_('Imports from:')
    for entry in SUBJECT.DIRECTORY_ENTRY_IMPORT:
        count = 0
        for i in entry.imports:
            count += 1
        print_('\t%s -> %i functions' % (entry.dll, count))

def callback():
    reportError('Callback not yet implemented')

# ----------------------------------------------------------------------------

menu_tree = [
    {'Section': 'Strings', 'Contents': [
        {'Option': 'Dump All', 'Callback': strings_display_all},
        {'Option': 'Search by keyword', 'Callback': strings_search},
    ]},
    {'Section': 'Imports', 'Contents': [
        {'Option': 'Dump All', 'Callback': imports_dump_all},
        {'Option': 'Search by keyword', 'Callback': imports_search},
    ]},
    {'Section': 'Exports', 'Contents': [
        {'Option': 'Dump All', 'Callback': exports_dump_all},
        {'Option': 'Search by keyword', 'Callback': exports_search},
        {'Option': 'Build VS #Pragma forwards',
            'Callback': exports_build_vs_pragma_forwards},
    ]},
    {'Section': 'Assembly', 'Contents': [
        {'Option': 'Disassemble at OEP', 'Callback': assembly_disassemble},
    ]},
    {'Section': 'Metadata', 'Contents': [
        {'Option': 'Binary Overview', 'Callback': metadata_subject_overview},
    ]},
    {'Section': 'Misc', 'Contents': [
        {'Option': 'Verify Checksum', 'Callback': misc_verify_checksum},
        {'Option': 'Generate Checksum', 'Callback': misc_generate_checksum},
        {'Option': 'Load new binary', 'Callback': loadSubject}
    ]},
]

# ----------------------------------------------------------------------------

class Menu:
    cur_section = None

    def __init__(self, menu_tree=None):
        self.tree = menu_tree

    def display(self):
        spacer()
        if self.cur_section is None:
            self.display_root()
        else:
            self.display_section()

    def display_root(self):
        index = 0
        for e in self.tree:
            print_('....[%i] %s' % (index, e['Section']))
            index += 1
        user_choice = None
        try:
            user_choice = int(getInput('Menu selection'))
        except ValueError:
            user_choice = None
        if user_choice >= index or user_choice < 0 or user_choice == None:
            reportError('Invalid menu selection')
            self.display()
        else:
            self.cur_section = user_choice
            self.display()

    def display_section(self):
        index = 0
        print_('....[+] %s' % self.tree[self.cur_section]['Section'])
        for e in self.tree[self.cur_section]['Contents']:
            print_('........[%i] %s' % (index, e['Option']))
            index += 1
        print_('........[%i] %s' % (index, 'Main menu'))
        user_choice = None
        try:
            user_choice = int(getInput('Menu selection'))
        except ValueError:
            user_choice = None
        if user_choice > index or user_choice < 0 or user_choice == None:
            reportError('Invalid menu selection')
            self.display()
        elif user_choice == index:
            self.cur_section = None
            self.display()
        else:
            # Bit of visual formatting happening here before the callback.
            spacer()
            drawLine()
            spacer()
            self.tree[self.cur_section]['Contents'][user_choice]['Callback']()
            spacer()
            drawLine()
            self.display()

# ----------------------------------------------------------------------------

AmnesiaMenu = Menu(menu_tree)
try:
    AmnesiaMenu.display()
except KeyboardInterrupt:
    print_('\n\nGoodbye.')
except Exception as e:
    reportError('Unhandled exception caught')
    reportError('%s' % e)
