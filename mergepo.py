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

    def matches_regex(self, regex, match_empty=True):
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

    def __init__(self, base_path, external_paths, output_path, regex, exported_path, all_references, ignore_duplicates, verbose_log):
        self.base_path = base_path
        self.external_paths = external_paths
        self.exported_path = exported_path
        self.output_path = output_path
        self.regex = regex
        self.all_references = all_references
        self.ignore_duplicates = ignore_duplicates
        self.verbose_log = verbose_log

        self.lines_added = self.lines_removed = 0
        self.added_entries, self.merged_entries, self.removed_entries = set(), set(), []

        self.preamble = ''

        self.entries = defaultdict(list)
        self.base_entries = []
        self.external_entries = []
        self.exported_entries = []

        self.matched_msgids = set()
        self.matched_exported_msgids = set()
        self.base_entries_by_msgid = defaultdict(list)
        self.external_entries_by_msgid = defaultdict(list)

        self.parse_entries()

        self.merge_base_external_entries()
        self.match_exported_entries()
        self.filter_output_entries()

    @property
    def paths(self):
        return [self.base_path, *self.external_paths] + ([self.exported_path] if self.exported_path else [])

    def parse_entries(self):
        entries_by_msgid = defaultdict(list)
        for path in self.paths:
            for entry in pofile(path):
                merger_entry = POMergerEntry(entry, path)
                self.entries[path].append(merger_entry)
                entries_by_msgid[entry.msgid].append(merger_entry)
                if merger_entry.matches_regex(self.regex):
                    self.matched_msgids.add(entry.msgid)
        self.parse_entries_lines()

    def parse_entries_lines(self):
        """
        Find the lines of each of the given entries given the file path
        Also sets the preamble of the output file to that of the base file
        :return:
        """
        for path in self.paths:
            entry_by_linenum = {entry.entry.linenum: entry for entry in self.entries[path]}
            with open(path, 'r', encoding='utf-8') as original_file:
                entry = None
                linenum = 1
                for line in original_file:
                    entry = entry_by_linenum.get(linenum, entry)
                    if entry:
                        entry.lines.append(line)
                    elif path == self.base_path:
                        self.preamble += line
                    linenum += 1

    def merge_base_external_entries(self):
        added_entries = {}
        for base_entry in self.entries[self.base_path]:
            if base_entry in added_entries:
                added_entries[base_entry].merge_occurrences(base_entry)
                self.removed_entries.append((base_entry, 'Duplicate entry'))
                self.lines_removed += len(base_entry.lines)
            else:
                self.base_entries.append(base_entry)
                self.base_entries_by_msgid[base_entry.entry.msgid].append(base_entry)
                added_entries[base_entry] = base_entry

        for path in self.external_paths:
            for external_entry in filter(lambda e: e.entry.msgid in self.matched_msgids, self.entries[path]):
                regex = self.regex if not self.all_references else '.'
                if external_entry in added_entries:
                    added_entries[external_entry].merge_occurrences(external_entry, regex)
                else:
                    external_entry.occurrences = set(filter_occurrences(external_entry.occurrences, regex))
                    self.external_entries.append(external_entry)
                    self.external_entries_by_msgid[external_entry.entry.msgid].append(external_entry)
                    added_entries[external_entry] = external_entry

    def match_exported_entries(self):
        for exported_entry in filter(lambda e: e.entry.msgid in self.matched_msgids, self.entries[self.exported_path]):
            msgid = exported_entry.entry.msgid
            self.matched_exported_msgids.add(msgid)

            regex = self.regex if not self.all_references else '.'
            matching_entries = self.base_entries_by_msgid[msgid] + self.external_entries_by_msgid[msgid]
            if not matching_entries:
                exported_entry.occurrences = set(filter_occurrences(exported_entry.occurrences, regex))
                self.exported_entries.append(exported_entry)
            elif len(matching_entries) == 1:
                matching_entries[0].match_occurrences(exported_entry, regex)
            else:
                ambiguous_occurrences = None
                for matching_entry in matching_entries:
                    old_occurrences = matching_entry.occurrences
                    matching_entry.match_occurrences(exported_entry, regex)

                    added_occurrences = matching_entry.occurrences - old_occurrences
                    matching_entry.occurrences -= added_occurrences

                    if ambiguous_occurrences is None:
                        ambiguous_occurrences = added_occurrences
                    else:
                        ambiguous_occurrences = ambiguous_occurrences.intersection(added_occurrences)

                if ambiguous_occurrences:
                    if self.ignore_duplicates:
                        POMerger.log_warning(f'Ignored entries with duplicate msgids: \'{msgid}\'')
                    else:
                        POMerger.resolve_ambiguous_occurrences(ambiguous_occurrences, matching_entries)

    def filter_output_entries(self):
        base_entries, base_entries_by_msgid = [], defaultdict(list)
        for base_entry in self.base_entries:
            msgid = base_entry.entry.msgid
            is_matched = msgid in self.matched_msgids
            removal_reason = ''
            if is_matched and self.exported_path and msgid not in self.matched_exported_msgids:
                removal_reason = 'Not in exported file'
            elif len(base_entry.occurrences) == 0:
                removal_reason = 'No references'

            if removal_reason:
                self.removed_entries.append((base_entry, removal_reason))
                self.lines_removed += len(base_entry.lines)
            else:
                base_entries.append(base_entry)
                base_entries_by_msgid[msgid].append(base_entry)
                lines_added = len(base_entry.added_occurrences)
                lines_removed = len(base_entry.removed_occurrences)
                if lines_added or lines_removed:
                    self.merged_entries.add(base_entry)
                    self.lines_added += lines_added
                    self.lines_removed += lines_removed
        self.base_entries = base_entries
        self.base_entries_by_msgid = base_entries_by_msgid

        external_entries, external_entries_by_msgid = [], defaultdict(list)
        for external_entry in self.external_entries:
            msgid = external_entry.entry.msgid
            in_exported = not self.exported_path or msgid in self.matched_exported_msgids
            no_references = len(external_entry.occurrences) == 0

            if in_exported and not no_references:
                external_entries.append(external_entry)
                external_entries_by_msgid[msgid].append(external_entry)
                self.added_entries.add(external_entry)
                self.lines_added += external_entry.__str__().count('\n')
        self.external_entries = external_entries
        self.external_entries_by_msgid = external_entries_by_msgid

        exported_entries = []
        for exported_entry in self.exported_entries:
            if len(exported_entry.occurrences):
                exported_entries.append(exported_entry)
                self.added_entries.add(exported_entry)
                self.lines_added += exported_entry.__str__().count('\n')
        self.exported_entries = exported_entries

    def run(self):
        for entry, removal_reason in sorted(self.removed_entries, key=lambda r: r[0].entry.linenum):
            POMerger.log_removed(entry, removal_reason)

        output_entries = self.base_entries + self.external_entries + self.exported_entries
        with open(self.output_path, 'w', encoding='utf-8') as output_file:
            output_file.write(self.preamble)
            for i, entry in enumerate(output_entries):
                entry_string = entry.__str__()

                # fix entries from other files than base getting concatenated on same line
                if i == len(output_entries) - 1:
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
        prefix = 'Added (EXPORTED)' if entry.source_path == self.exported_path else 'Added (EXTERNAL)'
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
    def resolve_ambiguous_occurrences(ambiguous_occurrences, merger_entries):
        """
        If there are occurrences to add and there exists two or more entries in the original file with same msgid
        then the ambiguity must be resolved or ignored (do not add new occurrences) if --ignore-duplicates flag is
        passed.
        """
        for occurrence in ambiguous_occurrences:
            _, i = pick(
                [f'{i + 1}) {e.entry.msgstr}' for i, e in enumerate(merger_entries)],
                f'Duplicate msgid found: \'{merger_entries[0].entry.msgid}\'\nChoose a msgstr for the below reference:'
                f'\n\n{occurrence_to_reference(occurrence)}',
                indicator='>'
            )
            merger_entries[i].occurrences.add(occurrence)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--base-path', required=True, help='Base file path')
    parser.add_argument('-m', '--external-paths', nargs='+', help='Paths for external files to merge into the base file', default=[])
    parser.add_argument('-e', '--exported-path', help='Exported file path')
    parser.add_argument('-o', '--output-path', required=True, help='Output file path')
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
