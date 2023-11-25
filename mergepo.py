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

    def __init__(self, entry, source_path):
        self.entry = entry
        self.source_path = source_path

        self.lines = []
        self.occurrences = set(entry.occurrences)

    def __str__(self, in_original_form=False):
        if in_original_form:
            return ''.join(self.lines)
        result = ''
        reference_index = 0
        were_added_occurrences_added = False
        added_occurrences = set()
        for line in self.lines:
            add_line = True
            if is_reference(line):
                occurrence = self.entry.occurrences[reference_index]
                add_line = occurrence in self.occurrences and occurrence not in added_occurrences
                reference_index += 1
                added_occurrences.add(occurrence)
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

    def __lt__(self, other):
        return self.__key() < other.__key()

    @property
    def added_occurrences(self):
        old_occurrences = set(self.entry.occurrences)
        return sorted([o for o in self.occurrences if o not in old_occurrences])

    @property
    def removed_occurrences(self):
        added_occurrences = set()
        removed_occurrences = []
        for occurrence in self.entry.occurrences:
            if occurrence not in self.occurrences or occurrence in added_occurrences:
                removed_occurrences.append(occurrence)
            added_occurrences.add(occurrence)
        return removed_occurrences

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
            self, original_paths, output_path,
            regex='.', exported_path=None, all_references=False,
            ignore_duplicates=False, verbose_log=False
    ):
        self.original_paths = original_paths
        self.base_original_path = original_paths[0]
        self.exported_path = exported_path
        self.output_path = output_path
        self.regex = regex
        self.all_references = all_references
        self.ignore_duplicates = ignore_duplicates
        self.verbose_log = verbose_log

        self.lines_added = self.lines_removed = 0
        self.added_entries, self.merged_entries, self.removed_entries = set(), set(), {}

        self.preamble = ''
        self.original_entries = []
        self.original_entries_by_msgid = defaultdict(list)
        self.exported_entries = []
        self.exported_entries_by_msgid = defaultdict(list)
        self.output_entries = []
        self.duplicate_entries_by_msgid = {}

        self.parse_files()
        self.correct_occurrences()
        self.compute_output_entries()

    def parse_files(self):
        for path in self.original_paths:
            entries = []
            for entry in pofile(path):
                original_entry = POMergerEntry(entry, path)
                self.original_entries.append(original_entry)
                self.original_entries_by_msgid[original_entry.entry.msgid].append(original_entry)
                entries.append(original_entry)
            self.parse_entries_lines(path, entries, set_preamble=(path == self.base_original_path))

        # entries that have same msgid but not same msgstr
        self.duplicate_entries_by_msgid = {
            m: list(set(e)) for m, e in self.original_entries_by_msgid.items() if len(set(e)) > 1
        }

        if self.exported_path:
            for entry in pofile(self.exported_path):
                exported_entry = POMergerEntry(entry, self.exported_path)
                self.exported_entries.append(exported_entry)
                self.exported_entries_by_msgid[exported_entry.entry.msgid].append(exported_entry)
            self.parse_entries_lines(self.exported_path, self.exported_entries)

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

    def correct_occurrences(self):
        # merge with duplicate
        added_original_entries = {}
        for original_entry in self.original_entries:
            if original_entry in added_original_entries:
                original_original_entry = added_original_entries[original_entry]
                original_original_entry.merge_occurrences(original_entry)
            else:
                added_original_entries[original_entry] = original_entry

        # match with exported
        resolved_duplicate_msgids = set()
        for original_entry in self.original_entries:
            exported_entry = self.exported_entries_by_msgid.get(original_entry.entry.msgid, [None])[0]
            if exported_entry:
                old_occurrences = original_entry.occurrences
                if self.all_references:
                    original_entry.match_occurrences(exported_entry)
                else:
                    original_entry.match_occurrences(exported_entry, self.regex)

                added_occurrences = original_entry.occurrences - old_occurrences
                msgid = original_entry.entry.msgid

                # resolve duplicates
                if msgid in self.duplicate_entries_by_msgid and added_occurrences:
                    original_entry.occurrences -= added_occurrences
                    if msgid not in resolved_duplicate_msgids:
                        all_occurrences = {o for e in self.duplicate_entries_by_msgid[msgid] for o in e.occurrences}
                        ambiguous_occurrences = {o for o in added_occurrences if o not in all_occurrences}
                        POMerger.resolve_duplicate_msgid(
                            sorted(ambiguous_occurrences), sorted(self.duplicate_entries_by_msgid[msgid])
                        )
                        resolved_duplicate_msgids.add(msgid)

        # don't add non matched occurrences in exported
        if not self.all_references:
            for exported_entry in self.exported_entries:
                exported_entry.occurrences = set(filter_occurrences(exported_entry.occurrences, self.regex))

    def compute_output_entries(self):
        """
        Compute entries that will be written to the output file
        """
        added_entries = set()

        # filter original
        for entry in self.original_entries:
            entry_in_base = entry.source_path == self.base_original_path
            entry_matches_regex = entry.matches_regex(self.regex)
            entry_in_exported = not bool(self.exported_path) or entry.entry.msgid in self.exported_entries_by_msgid

            removal_reason = False
            if entry in added_entries:
                removal_reason = 'Duplicate entry'
            elif entry_matches_regex and not entry_in_exported:
                removal_reason = 'Not in exported file'
            elif len(entry.occurrences) == 0:
                removal_reason = 'No references'

            if entry_in_base:
                if removal_reason:
                    self.removed_entries[entry] = removal_reason
                    self.lines_removed += entry.__str__(in_original_form=True).count('\n')
                else:
                    self.output_entries.append(entry)
                    lines_added, lines_removed = len(entry.added_occurrences), len(entry.removed_occurrences)
                    if lines_added or lines_removed:
                        self.merged_entries.add(entry)
                        self.lines_added += lines_added
                        self.lines_removed += lines_removed
                    added_entries.add(entry)
            elif not removal_reason:
                self.output_entries.append(entry)
                self.added_entries.add(entry)
                self.lines_added += entry.__str__().count('\n')
                added_entries.add(entry)

        # add exported
        for entry in self.exported_entries:
            entry_matches_regex = entry.matches_regex(self.regex, match_empty=False)
            if entry_matches_regex and entry.entry.msgid not in self.original_entries_by_msgid:
                self.output_entries.append(entry)
                self.added_entries.add(entry)
                self.lines_added += entry.__str__().count('\n')
                added_entries.add(entry)

    def run(self):
        with open(self.output_path, 'w', encoding='utf-8') as output_file:
            output_file.write(self.preamble)
            for i, entry in enumerate(self.output_entries):
                is_modified = entry in self.added_entries or entry in self.merged_entries
                entry_string = entry.__str__(in_original_form=not is_modified)

                # fix entries from other files than base getting concatenated on same line
                if i == len(self.output_entries) - 1:
                    entry_string = entry_string.rstrip('\n')
                elif not entry_string.endswith('\n\n'):
                    entry_string += '\n\n'

                output_file.write(entry_string)
                if entry in self.merged_entries:
                    POMerger.log_merged(entry)
                elif entry in self.added_entries:
                    self.log_added(entry)
                elif self.verbose_log:
                    POMerger.log_unaffected(entry)
            for entry, removal_reason in self.removed_entries.items():
                POMerger.log_removed(entry, removal_reason)

        if self.lines_added == self.lines_removed == 0:
            print('No changes done, original file is identical to output file')
        else:
            self.log_statistics()

    def log_statistics(self):
        entries = (
            colored(str(len(self.added_entries)) + ' entries', 'green'),
            colored(str(len(self.merged_entries)) + ' entries', 'cyan'),
            colored(str(len(self.removed_entries)) + ' entries', 'red')
        )
        lines = (
            colored(str(self.lines_added) + ' lines', 'green'),
            colored(str(self.lines_removed) + ' lines', 'red')
        )
        print()
        print('Added {}, merged {} and removed {}'.format(*entries))
        print('Added {} and removed {}'.format(*lines))

    def log_added(self, entry):
        prefix = 'NEW (EXPORTED)' if entry.source_path == self.exported_path else 'NEW (ORIGINAL)'
        print(colored(f'{prefix}: \'{entry.entry.msgid}\'', 'green'))

    @staticmethod
    def log_warning(warning):
        print(colored(warning, 'yellow'))

    @staticmethod
    def log_unaffected(entry):
        print(f'Unaffected \'{entry.entry.linenum}\': {entry.entry.msgid}')

    @staticmethod
    def log_merged(entry):
        print(colored(f'Merged {entry.entry.linenum}: \'{entry.entry.msgid}\'', 'cyan'))

    @staticmethod
    def log_removed(entry, removal_reason):
        print(colored(f'Removed {entry.entry.linenum}: \'{entry.entry.msgid}\' ({removal_reason})', 'red'))

    @staticmethod
    def resolve_duplicate_msgid(ambiguous_occurrences, entries):
        """
        If there are occurrences to add and there exists two or more entries in the original file with same msgid
        then the ambiguity must be resolved or ignored (do not add new occurrences) if --ignore-duplicates flag is
        passed.
        """
        for occurrence in ambiguous_occurrences:
            _, i = pick(
                [f'{i + 1}) {e.entry.msgstr}' for i, e in enumerate(entries)],
                f'Duplicate msgid found: \'{entries[0].entry.msgid}\'\nChoose a msgstr for the below reference:'
                f'\n\n{occurrence_to_reference(occurrence)}',
                indicator='>'
            )
            entries[i].occurrences.add(occurrence)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--original-paths', required=True, nargs='+', help='Original file(s) path(s)')
    parser.add_argument('-o', '--output-path', required=True, help='Output file path')
    parser.add_argument('-e', '--exported-path', help='Exported file path')
    parser.add_argument('-r', '--regex',
                        help='Match only entries that have references matching this regex. default: all', default='.')
    parser.add_argument('-a', '--all-references', action='store_true',
                        help='Whether to merge all different references present in '
                             'matched entries or add only those references that match the'
                             ' specified regex')
    parser.add_argument('-i', '--ignore-duplicates', action='store_true',
                        help='If this flag is passed then no new references will be added'
                             ' to entries with duplicate msgids')
    parser.add_argument('-v', '--verbose-log', action='store_true',
                        help='If this flag is passed then extra information is logged to the console')

    po_merger = POMerger(**vars(parser.parse_args()))
    po_merger.run()
