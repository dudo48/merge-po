import argparse
import re
from collections import defaultdict

from pick import pick
from polib import pofile
from termcolor import colored


# functions to detect the type of po line
def is_reference(line):
    return line.startswith('#:')


def is_line_after_references(line):
    symbols = ['#,', '#|', 'msgid', '"', 'msgstr']
    return any(line.startswith(symbol) for symbol in symbols)


def occurrence_to_reference(occurrence):
    """
    Converts an occurrence tuple to a reference line
    :param occurrence:
    :return:
    """
    return '#: ' + (f'{occurrence[0]}:{occurrence[1]}' if occurrence[1] else occurrence[0])


def filter_occurrences(occurrences, regex):
    """
    Returns occurrences that match the set
    :param occurrences:
    :param regex:
    :return:
    """
    return [o for o in occurrences if re.search(regex, occurrence_to_reference(o))]


class POMergerEntry:
    """
    Encapsulates entries in original file
    """

    def __init__(self, entry, is_matched=False):
        self.entry = entry
        self.is_matched = is_matched

        self.lines = []
        self.occurrences = set(entry.occurrences)

    def __str__(self, in_original_form=False):
        if in_original_form:
            return ''.join(self.lines)
        result = ''
        reference_index = 0
        were_added_occurrences_added = False
        for line in self.lines:
            add_line = True
            if is_reference(line):
                add_line = self.entry.occurrences[reference_index] in self.occurrences
                reference_index += 1
            elif is_line_after_references(line) and not were_added_occurrences_added:
                for occurrence in self.added_occurrences:
                    result += f'{occurrence_to_reference(occurrence)}\n'
                were_added_occurrences_added = True
            if add_line:
                result += line
        return result

    def __repr__(self):
        return f'({self.entry.msgid}, {self.entry.msgstr})'

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other):
        if isinstance(other, POMergerEntry):
            return self.__key() == other.__key()
        return NotImplemented

    @property
    def added_occurrences(self):
        old_occurrences = set(self.entry.occurrences)
        return sorted([o for o in self.occurrences if o not in old_occurrences])\

    @property
    def removed_occurrences(self):
        return [o for o in self.entry.occurrences if o not in self.occurrences]

    def __key(self):
        return self.entry.msgid, self.entry.msgstr


    def merge_occurrences(self, other, regex='.'):
        """
        Merge occurrences of current object with another POMergerEntry object (union on occurrences matching regex only)
        :param other:
        :param regex:
        :return:
        """
        filtered_other_occurrences = set(filter_occurrences(other.occurrences, regex))
        self.occurrences = self.occurrences.union(filtered_other_occurrences)

    def match_occurrences(self, other, regex='.'):
        """
        Set occurrences of current object to match another POMergerEntry object's occurrences (occurrences matching regex only)
        :param other:
        :param regex:
        :return:
        """
        filtered_other_occurrences = set(filter_occurrences(other.occurrences, regex))
        filtered_self_occurrences = set(filter_occurrences(self.occurrences, regex))

        # add then remove
        self.occurrences = self.occurrences.union(filtered_other_occurrences)
        self.occurrences = self.occurrences - (filtered_self_occurrences - other.occurrences)

    def matches_regex(self, regex='.', match_empty=True):
        """
        Checks whether the entry matches the given regex
        If match_empty is True then entries with empty occurrence list will be matched
        :param regex:
        :param match_empty:
        :return:
        """
        occurrences = self.occurrences.union(self.entry.occurrences)
        return any(filter_occurrences(occurrences, regex)) or (match_empty and not self.entry.occurrences)


class POMerger:
    """
    Merges two PO files where one is the original(current) file and the other is exported from Odoo server
    """

    def __init__(
            self, original_path, exported_path,
            output_path, regex='.', all_references=False,
            ignore_duplicates=False, verbose_log=False
    ):
        self.original_path = original_path
        self.exported_path = exported_path
        self.output_path = output_path
        self.regex = regex
        self.all_references = all_references
        self.ignore_duplicates = ignore_duplicates
        self.verbose_log = verbose_log

        self.lines_added = self.lines_removed = 0

        self.original_entries = []
        self.original_entries_by_msgid = defaultdict(list)
        self.exported_entries = []
        self.exported_entries_by_msgid = defaultdict(list)
        self.preamble = ''

        self.parse_files()
        self.correct_occurrences()
        self.resolve_duplicate_msgids()

    def parse_files(self):
        for entry in pofile(self.original_path):
            original_entry = POMergerEntry(entry)
            self.original_entries.append(original_entry)
            self.original_entries_by_msgid[original_entry.entry.msgid].append(original_entry)
        self.parse_entries_lines(self.original_path, self.original_entries, set_preamble=True)

        for entry in pofile(self.exported_path):
            exported_entry = POMergerEntry(entry)
            self.exported_entries.append(exported_entry)
            self.exported_entries_by_msgid[exported_entry.entry.msgid].append(exported_entry)
        self.parse_entries_lines(self.exported_path, self.exported_entries)

    def correct_occurrences(self):
        # don't add non matched occurrences in exported
        if not self.all_references:
            for exported_entry in self.exported_entries:
                exported_entry.occurrences = set(filter_occurrences(exported_entry.occurrences, self.regex))
        for original_entry in self.original_entries:
            exported_entry = self.exported_entries_by_msgid.get(original_entry.entry.msgid, [None])[0]
            if exported_entry:
                if self.all_references:
                    original_entry.match_occurrences(exported_entry)
                else:
                    original_entry.match_occurrences(exported_entry, self.regex)

    def find_duplicate_msgid_entries(self):
        duplicate_msgid_entries = {m: e for m, e in self.original_entries_by_msgid.items() if len(e) > 1}
        result = {}

        # filter out entries with same msgstr
        for msgid, entries in duplicate_msgid_entries.items():
            entry_list, entry_set = [], set()
            for entry in entries:
                if entry not in entry_set and entry.matches_regex(self.regex):
                    entry_list.append(entry)
                entry_set.add(entry)
            if len(entry_list) > 1:
                result[msgid] = entry_list
        return result

    def resolve_duplicate_msgids(self):
        """
        If there are occurrences to add and there exists two or more entries in the original file with same msgid
        then the ambiguity must be resolved or ignored(do not add new occurrences) if --ignore-duplicates flag is
        passed.
        """

        duplicate_msgid_entries = self.find_duplicate_msgid_entries()
        for msgid, entries in duplicate_msgid_entries.items():
            all_added_occurrences = [o for e in entries for o in e.added_occurrences]
            excluded_occurrences = {o for e in entries for o in e.entry.occurrences}
            ambiguous_occurrences = []
            for occurrence in all_added_occurrences:
                if occurrence not in excluded_occurrences:
                    ambiguous_occurrences.append(occurrence)
                    excluded_occurrences.add(occurrence)
            for entry in entries:
                entry.occurrences = set(entry.entry.occurrences)
            if self.ignore_duplicates:
                if ambiguous_occurrences:
                    POMerger.log_warning(f'Ignored duplicate entries with msgid: \'{msgid}\'')
                continue
            for occurrence in ambiguous_occurrences:
                _, i = pick(
                    [e.entry.msgstr for e in entries],
                    f'Duplicate msgid found: \'{msgid}\'\nChoose a msgstr for the below reference:'
                    f'\n\n{occurrence_to_reference(occurrence)}',
                    indicator='>'
                )
                entries[i].occurrences.add(occurrence)

    def parse_entries_lines(self, path, entries, set_preamble=False):
        """
        Find the lines of each of the given entries given the file path
        :param entries:
        :param path:
        :param set_preamble: Whether to set the preamble of the object to this file's preamble
        :return:
        """
        if not entries:
            return
        if set_preamble:
            self.preamble = ''
        entry_by_linenum = {entry.entry.linenum: entry for entry in entries}
        with open(path, 'r', encoding='utf-8') as original_file:
            entry = None
            linenum = 1
            for line in original_file:
                entry = entry_by_linenum.get(linenum, entry)
                if entry:
                    entry.lines.append(line)
                elif set_preamble:
                    self.preamble += line
                linenum += 1

    def log_statistics(self, added_count, merged_count, removed_count):
        entries = (
            colored(str(added_count) + ' entries', 'green'),
            colored(str(merged_count) + ' entries', 'cyan'),
            colored(str(removed_count) + ' entries', 'red')
        )
        lines = (
            colored(str(self.lines_added) + ' lines', 'green'),
            colored(str(self.lines_removed) + ' lines', 'red')
        )
        print()
        print('Added {}, merged {} and removed {}'.format(*entries))
        print('Added {} and removed {}'.format(*lines))

    def run(self):
        added_count = merged_count = removed_count = 0
        with open(self.output_path, 'w', encoding='utf-8') as output_file:
            output_file.write(self.preamble)
            added_entries = set()
            for entry in self.original_entries:
                if not entry.matches_regex(self.regex):
                    output_file.write(entry.__str__(in_original_form=True))
                    if self.verbose_log:
                        POMerger.log_unaffected(entry)
                    continue
                add_entry = True
                removal_reason = ''

                duplicate_entry = entry in added_entries
                not_in_exported = entry.entry.msgid not in self.exported_entries_by_msgid
                no_references = len(entry.occurrences) == 0
                if duplicate_entry or not_in_exported or no_references:
                    if duplicate_entry:
                        removal_reason = 'Duplicate entry'
                    elif not_in_exported:
                        removal_reason = 'Not in exported file'
                    elif no_references:
                        removal_reason = 'No references'
                    add_entry = False
                    removed_count += 1
                    self.lines_removed += entry.__str__().count('\n')
                    POMerger.log_removed(entry, removal_reason)

                if add_entry:
                    output_file.write(entry.__str__())
                    added_entries.add(entry)
                    lines_added, lines_removed = len(entry.added_occurrences), len(entry.removed_occurrences)
                    if lines_added or lines_removed:
                        merged_count += 1
                        POMerger.log_merged(entry)
                        self.lines_added += lines_added
                        self.lines_removed += lines_removed
                    elif self.verbose_log:
                        POMerger.log_unaffected(entry)

            for entry in self.exported_entries:
                if entry.entry.msgid not in self.original_entries_by_msgid and entry.matches_regex(self.regex, match_empty=False):
                    output_file.write(entry.__str__())
                    added_count += 1
                    self.lines_added += entry.__str__().count('\n')
                    POMerger.log_added(entry)

        if self.lines_added == self.lines_removed == 0:
            print('Original file is up-to-date with exported file')
        else:
            self.log_statistics(added_count, merged_count, removed_count)

    @staticmethod
    def log_warning(warning):
        print(colored(warning, 'yellow'))

    @staticmethod
    def log_unaffected(entry):
        print(f'{entry.entry.linenum}: {entry.entry.msgid}')

    @staticmethod
    def log_merged(entry):
        print(colored(f'{entry.entry.linenum}: {entry.entry.msgid}', 'cyan'))

    @staticmethod
    def log_removed(entry, removal_reason):
        print(colored(f'{entry.entry.linenum}: {entry.entry.msgid} ({removal_reason})', 'red'))

    @staticmethod
    def log_added(entry):
        print(colored(f'NEW: {entry.entry.msgid}', 'green'))


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
    parser.add_argument('-v', '--verbose-log', action='store_true',
                        help='If this flag is sent then extra information is logged to the console')

    po_merger = POMerger(**vars(parser.parse_args()))
    po_merger.run()
