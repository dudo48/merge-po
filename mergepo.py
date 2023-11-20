import argparse
import re
from itertools import groupby

from pick import pick
from polib import pofile
from termcolor import colored


# functions to detect the type of a po line
def is_reference(line):
    return line.startswith('#:')


def is_line_after_references(line):
    symbols = ['#,', '#|', 'msgid', '"', 'msgstr']
    return any(line.startswith(symbol) for symbol in symbols)


# return occurrence tuple converted to reference string
def occurrence_to_reference(occurrence):
    return '#: ' + (f'{occurrence[0]}:{occurrence[1]}' if occurrence[1] else occurrence[0])


# returns occurrences of the entry that match the regex
def occurrences_matching(occurrences, regex):
    return [occurrence for occurrence in occurrences if re.search(regex, occurrence_to_reference(occurrence))]


# returns whether the entry's occurrences matches the given regex
def entry_matches_regex(entry, regex, match_empty=True):
    # entries with empty occurrences list are matched depending on match_empty
    return bool(occurrences_matching(entry.occurrences, regex)) or (match_empty and not entry.occurrences)

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

        self.added_occurrences = []
        self.removed_occurrences = set()

    @property
    def write_to_output(self):
        return not self.is_matched or (self.in_exported and not self.is_duplicate and not self.no_more_references)

    @property
    def no_more_references(self):
        return self.removed_occurrences >= set(self.entry.occurrences).union(set(self.added_occurrences))


class POExportedEntry(POBaseEntry):
    """
    Encapsulates entries in exported file
    """

    def __init__(self, entry, is_matched, is_new):
        super().__init__(entry, is_matched)
        self.is_new = is_new
        self.excluded_occurrences = set()


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
            exported_entry = POExportedEntry(
                entry=entry,
                is_matched=entry_matches_regex(entry, self.regex, match_empty=False),
                is_new=entry.msgid not in original_entries_msgids
            )
            if not self.all_references:
                matching_occurrences = set(occurrences_matching(exported_entry.entry.occurrences, self.regex))
                exported_entry.excluded_occurrences = set(exported_entry.entry.occurrences) - matching_occurrences
            self.exported_entry_by_msgid[entry.msgid] = exported_entry

        parsed_entries_msgs = set()
        for entry in pofile(self.original_path):
            original_entry = POOriginalEntry(
                entry=entry,
                is_matched=entry_matches_regex(entry, self.regex),
                in_exported=entry.msgid in self.exported_entry_by_msgid,
                is_duplicate=(entry.msgid, entry.msgstr) in parsed_entries_msgs
            )
            if entry.msgid in self.exported_entry_by_msgid:
                exported_entry = self.exported_entry_by_msgid[entry.msgid]

                # find occurrences to add
                not_in_original = set(exported_entry.entry.occurrences) - set(entry.occurrences)
                if not self.all_references:
                    not_in_original = occurrences_matching(not_in_original, self.regex)
                original_entry.added_occurrences = sorted(not_in_original)

                # compute occurrences to remove
                not_in_exported = set(entry.occurrences) - set(exported_entry.entry.occurrences)
                if not self.all_references:
                    not_in_exported = occurrences_matching(not_in_exported, self.regex)
                original_entry.removed_occurrences = set(not_in_exported)

            self.original_entry_by_linenum[entry.linenum] = original_entry
            parsed_entries_msgs.add((entry.msgid, entry.msgstr))

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
                    original_entry.added_occurrences = []
                print(colored(f'Ignored duplicate entries with msgid: \'{msgid}\'', 'yellow'))
                continue

            all_added_occurrences = {o for e in original_entries for o in e.added_occurrences}
            all_current_occurrences = {o for e in original_entries for o in e.entry.occurrences}
            ambiguous_occurrences = all_added_occurrences - all_current_occurrences
            for original_entry in original_entries:
                original_entry.added_occurrences = []
            for occurrence in sorted(ambiguous_occurrences):
                _, i = pick(
                    [e.entry.msgstr for e in original_entries],
                    f'Duplicate msgid found: \'{msgid}\'\nChoose a msgstr for the below reference:'
                    f'\n\n{occurrence_to_reference(occurrence)}',
                    indicator='>'
                )
                original_entries[i].added_occurrences.append(occurrence)

    def merge_and_remove(self):
        """
        Merge existing entries by adding missing references and removing invalid ones
        :return:
        """
        with open(self.output_path, 'w', encoding='utf-8') as output_file, \
             open(self.original_path, 'r', encoding='utf-8') as original_file:
            linenum, reference_index = 1, 0
            original_entry = occurrence = None
            passed_references = False
            for line in original_file:
                original_entry = self.original_entry_by_linenum.get(linenum, original_entry)
                write_line = True

                if linenum in self.original_entry_by_linenum:
                    passed_references = False

                # occurrence matching current reference
                if original_entry and is_reference(line):
                    occurrence = original_entry.entry.occurrences[reference_index]

                if original_entry and original_entry.is_matched:
                    # remove entry
                    if not original_entry.write_to_output:
                        write_line = False
                        self.removed_entries_linenums.add(original_entry.entry.linenum)

                    # remove reference
                    elif is_reference(line) and occurrence in original_entry.removed_occurrences:
                        write_line = False
                        self.merged_entries_linenums.add(original_entry.entry.linenum)

                    # add references
                    elif is_line_after_references(line) and not passed_references and original_entry.added_occurrences:
                        # add new references sorted so the result is always the same
                        for occurrence in sorted(original_entry.added_occurrences):
                            output_file.write(f'{occurrence_to_reference(occurrence)}\n')
                            self.lines_added += 1
                        self.merged_entries_linenums.add(original_entry.entry.linenum)

                if write_line:
                    output_file.write(line)
                else:
                    self.lines_removed += 1

                if is_line_after_references(line):
                    passed_references = True
                reference_index = reference_index + 1 if is_reference(line) else 0
                linenum += 1

    def add_new(self):
        """
        Write new entries at the end of the file
        """
        new_entries_linenums = set()
        exported_entry_by_linenum = {}
        for _, exported_entry in self.exported_entry_by_msgid.items():
            exported_entry_by_linenum[exported_entry.entry.linenum] = exported_entry
            if  exported_entry.is_matched and exported_entry.is_new:
                new_entries_linenums.add(exported_entry.entry.linenum)
    
        if not new_entries_linenums:
            return
        exported_entry_by_linenum = {e.entry.linenum: e for _, e in self.exported_entry_by_msgid.items()}
        with open(self.output_path, 'a', encoding='utf-8') as output_file, \
             open(self.exported_path, 'r', encoding='utf-8') as exported_file:
            exported_entry = occurrence = None
            linenum, reference_index = 1, 0
            for line in exported_file:
                exported_entry = exported_entry_by_linenum.get(linenum, exported_entry)

                # occurrence matching current reference
                if exported_entry and is_reference(line):
                    occurrence = exported_entry.entry.occurrences[reference_index]

                if exported_entry and exported_entry.entry.linenum in new_entries_linenums:
                    if not is_reference(line) or occurrence not in exported_entry.excluded_occurrences:
                        output_file.write(line)
                        self.lines_added += 1
                        self.new_entries_msgids.add(exported_entry.entry.msgid)
                reference_index = reference_index + 1 if is_reference(line) else 0
                linenum += 1

    def run(self):
        self.merge_and_remove()
        self.add_new()

        if self.lines_added == self.lines_removed == 0:
            print('Original file is up-to-date with exported file')
        else:
            for msgid in sorted(self.new_entries_msgids):
                print(colored(f'Added entry:   \'{msgid}\'', 'green'))
            for linenum in sorted(self.merged_entries_linenums):
                print(colored(f'Merged entry at line {linenum}:  \'{self.original_entry_by_linenum[linenum].entry.msgid}\'', 'cyan'))
            for linenum in sorted(self.removed_entries_linenums):
                original_entry = self.original_entry_by_linenum[linenum]
                removal_reason = ''
                if original_entry.is_duplicate:
                    removal_reason = 'Duplicate entry'
                elif not original_entry.in_exported:
                    removal_reason = 'Entry not in exported file'
                elif original_entry.no_more_references:
                    removal_reason = 'Entry does not have references'
                print(colored(f'Removed entry at line {linenum}: \'{original_entry.entry.msgid}\' ({removal_reason})', 'red'))

            entries = (
                colored(f'{len(self.new_entries_msgids)} entries', 'green'),
                colored(f'{len(self.merged_entries_linenums)} entries', 'cyan'),
                colored(f'{len(self.removed_entries_linenums)} entries', 'red')
            )
            lines = (
                colored(f'{self.lines_added} line(s)', 'green'),
                colored(f'{self.lines_removed} line(s)', 'red')
            )
            print('Added {}, merged {} and removed {}'.format(*entries))
            print('Added {} and removed {}'.format(*lines))


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
