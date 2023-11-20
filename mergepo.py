import argparse
import re
from itertools import groupby

from polib import pofile
from pick import pick
from termcolor import colored


# functions to detect the type of a po line
def is_reference(line):
    return line.startswith('#:')


def is_flag(line):
    return line.startswith('#,')


def is_msgid(line):
    return line.startswith('msgid')


def is_first_line_after_references(line):
    return is_flag(line) or is_msgid(line)


# return occurrence tuple converted to reference string
def occurrence_to_reference(occ):
    return '#: ' + (f'{occ[0]}:{occ[1]}' if occ[1] else occ[0])


# returns occurrences of the entry that match the regex
def occurrences_matching(occurrences, regex):
    return [occ for occ in occurrences if re.search(regex, occurrence_to_reference(occ))]


# returns whether the entry's occurrences matches the given regex
def entry_matches_regex(entry, regex):
    # entries with empty occurrences list are always matched
    return bool(occurrences_matching(entry.occurrences, regex)) or not entry.occurrences

class POBaseEntry:
    """
        Base class for POOriginalEntry and POExportedEntry
    """

    def __init__(self, entry, is_matched):
        self.entry = entry
        self.is_matched = is_matched

    def __str__(self):
        return f'({self.entry.msgid}, {self.entry.msgstr})'

    def __repr__(self):
        return f'({self.entry.msgid}, {self.entry.msgstr})'


class POOriginalEntry(POBaseEntry):
    """
        Encapsulates entries in original file
    """

    def __init__(self, entry, is_matched, in_exported, is_duplicate):
        super().__init__(entry, is_matched)
        self.in_exported = in_exported
        self.is_duplicate = is_duplicate

        self.occurrences_to_add = []
        self.occurrences_to_remove = set()

    @property
    def write_to_output(self):
        return not self.is_matched or (self.in_exported and not self.is_duplicate and not self.no_more_references)

    @property
    def no_more_references(self):
        return self.occurrences_to_remove >= set(self.entry.occurrences).union(set(self.occurrences_to_add))


class POExportedEntry(POBaseEntry):
    """
        Encapsulates entries in exported file
    """

    def __init__(self, entry, is_matched, is_new):
        super().__init__(entry, is_matched)
        self.is_new = is_new


class POMerger:
    """
        Merges two PO files where one is the original(current) file and the other is exported from Odoo server
    """

    def __init__(self, original_path, exported_path, output_path, regex='.', all_references=False, ignore_duplicates=False):
        self.original_path = original_path
        self.exported_path = exported_path
        self.output_path = output_path
        self.regex = regex
        self.all_references = all_references
        self.ignore_duplicates = ignore_duplicates

        # statistical attributes
        self.lines_added = self.lines_removed = 0
        self.merged_entries_linenums = set()
        self.removed_entries_linenums = set()
        self.new_entries_msgids = set()

        self.exported_entry_by_msgid = {}
        self.original_entry_by_linenum = {}

        self.parse_files()
        self.resolve_duplicate_msgids()

    def parse_files(self):
        original_entries_msgids = {entry.msgid for entry in pofile(self.original_path)}
        for entry in pofile(self.exported_path):
            self.exported_entry_by_msgid[entry.msgid] = POExportedEntry(
                entry=entry,
                is_matched=entry_matches_regex(entry, self.regex),
                is_new=entry.msgid not in original_entries_msgids
            )

        parsed_entries = set()
        for entry in pofile(self.original_path):
            original_entry = POOriginalEntry(
                entry=entry,
                is_matched=entry_matches_regex(entry, self.regex),
                in_exported=entry.msgid in self.exported_entry_by_msgid,
                is_duplicate=entry in parsed_entries
            )
            if entry.msgid in self.exported_entry_by_msgid:
                exported_entry = self.exported_entry_by_msgid[entry.msgid]

                # find occurrences to add
                not_in_original = set(exported_entry.entry.occurrences) - set(entry.occurrences)
                if not self.all_references:
                    not_in_original = occurrences_matching(not_in_original, self.regex)
                original_entry.occurrences_to_add = sorted(not_in_original)

                # compute occurrences to remove
                not_in_exported = set(entry.occurrences) - set(exported_entry.entry.occurrences)
                if not self.all_references:
                    not_in_exported = occurrences_matching(not_in_exported, self.regex)
                original_entry.occurrences_to_remove = set(not_in_exported)

            self.original_entry_by_linenum[entry.linenum] = original_entry
            parsed_entries.add(entry)

    def resolve_duplicate_msgids(self):
        """
            If there is occurrences to add and there exists two or more entries in the original file with same msgid
            then the ambiguity must be resolved or ignored(do not add new occurrences) if --ignore-duplicates flag is
            passed.
        """
        # choice is available only for matched and not to-remove entries
        original_entries = [e for _, e in self.original_entry_by_linenum.items() if e.write_to_output and e.is_matched]

        sorted_original_entries = sorted(original_entries, key=lambda e: (e.entry.msgid, e.entry.msgstr))
        original_entries_by_msgid = {m: list(e) for m, e in groupby(sorted_original_entries, key=lambda e: e.entry.msgid)}

        duplicate_original_entries_by_msgid = {m: e for m, e in original_entries_by_msgid.items() if len(e) > 1}
        for msgid, original_entries in duplicate_original_entries_by_msgid.items():
            if self.ignore_duplicates:
                for original_entry in original_entries:
                    original_entry.occurrences_to_add = []
                print(colored(f'Ignored duplicate entries with msgid: \'{msgid}\'', 'yellow'))
                continue

            all_occurrences_to_add = {o for e in original_entries for o in e.occurrences_to_add}
            all_current_occurrences = {o for e in original_entries for o in e.entry.occurrences}
            ambiguous_occurrences = all_occurrences_to_add - all_current_occurrences
            for original_entry in original_entries:
                original_entry.occurrences_to_add = []
            for occurrence in sorted(ambiguous_occurrences):
                _, i = pick(
                    [e.entry.msgstr for e in original_entries],
                    f'Duplicate msgid found: \'{msgid}\'\nChoose a msgstr for the below reference:'
                    f'\n\n{occurrence_to_reference(occurrence)}',
                    indicator='>'
                )
                original_entries[i].occurrences_to_add.append(occurrence)

    def merge_and_remove(self):
        with open(self.output_path, 'w', encoding='utf-8') as output_file, \
             open(self.original_path, 'r', encoding='utf-8') as original_file:
            linenum = reference_index = 0
            original_entry = None
            for line in original_file:
                linenum += 1
                original_entry = self.original_entry_by_linenum.get(linenum, original_entry)
                write_line = True

                if original_entry and original_entry.is_matched:
                    # remove duplicate or not in exported entries
                    if not original_entry.write_to_output:
                        write_line = False
                        self.removed_entries_linenums.add(original_entry.entry.linenum)

                    # remove reference
                    if is_reference(line) and original_entry.entry.occurrences[reference_index] in original_entry.occurrences_to_remove:
                        write_line = False
                        self.merged_entries_linenums.add(original_entry.entry.linenum)

                    # add references
                    elif is_first_line_after_references(line) and original_entry.occurrences_to_add:
                        # add new references sorted so the result is always the same
                        for occurrence in sorted(original_entry.occurrences_to_add):
                            output_file.write(f'{occurrence_to_reference(occurrence)}\n')
                            self.lines_added += 1
                        self.merged_entries_linenums.add(original_entry.entry.linenum)

                if write_line:
                    output_file.write(line)
                else:
                    self.lines_removed += 1
                reference_index = reference_index + 1 if is_reference(line) else 0

    def add_new(self):
        new_entries = sorted([e for _, e in self.exported_entry_by_msgid.items() if e.is_new], key=lambda e: e.entry.msgid)
        with open(self.output_path, 'a', encoding='utf-8') as output_file:
            if new_entries:
                output_file.write('\n')
            for entry in new_entries:
                output_file.write(f'\n{str(entry.entry)}')
                self.lines_added += str(entry.entry).count('\n')
                self.new_entries_msgids.add(entry.entry.msgid)

    def run(self):
        self.merge_and_remove()
        self.add_new()

        for msgid in sorted(self.new_entries_msgids):
            print(colored(f'Added entry:   \'{msgid}\'', 'green'))
        for linenum in sorted(self.merged_entries_linenums):
            print(colored(f'Merged entry:  \'{self.original_entry_by_linenum[linenum].entry.msgid}\' at line {linenum}', 'cyan'))
        for linenum in sorted(self.removed_entries_linenums):
            original_entry = self.original_entry_by_linenum[linenum]
            removal_reason = ''
            if original_entry.is_duplicate:
                removal_reason = 'duplicate entry'
            elif not original_entry.in_exported:
                removal_reason = 'entry not in exported file'
            elif original_entry.no_more_references:
                removal_reason = 'entry does not have references'
            print(colored(f'Removed entry: \'{original_entry.entry.msgid}\' ({removal_reason})', 'red'))

        print(
            'Added ' + colored(f'{len(self.new_entries_msgids)} entries', 'green')
            + ', merged ' + colored(f'{len(self.merged_entries_linenums)} entries', 'cyan')
            + ' and removed ' + colored(f'{len(self.removed_entries_linenums)} entries', 'red')
        )
        print(
            'Added ' + colored(f'{self.lines_added} line(s)', 'green')
            + ' and removed ' + colored(f'{self.lines_removed} line(s)', 'red')
        )


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--original-path', required=True, help='Original file path')
    parser.add_argument('-e', '--exported-path', required=True, help='Exported file path')
    parser.add_argument('-o', '--output-path', required=True, help='Output file path')
    parser.add_argument('-r', '--regex',
                        help='Match only entries that have occurrences matching this regex. default: all', default='.')
    parser.add_argument('-a', '--all-references', action='store_true',
                        help='Whether to add all different references present in '
                             'the exported file or add only those that match the'
                             ' specified regex')
    parser.add_argument('-i', '--ignore-duplicates', action='store_true',
                        help='If this flag is sent then duplicates no new references will be added'
                             ' to entries with non-unique msgids')

    po_merger = POMerger(**vars(parser.parse_args()))
    po_merger.run()
