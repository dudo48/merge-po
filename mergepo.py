"""
The happiness of most people is not ruined by great catastrophes or fatal errors,
but by the repetition of slowly destructive little things.
    - Ernest Dimnet
"""
import argparse
import re
from collections import defaultdict

from pick import pick
from polib import pofile
from termcolor import colored
import os


# functions to detect the type of po line
def is_reference(line):
    return line.startswith('#:')


def is_msgtr(line):
    return line.startswith('msgstr')


def is_line_after_references(line):
    symbols = ['#,', '#|', 'msgid', '"', 'msgstr']
    return any(line.startswith(symbol) for symbol in symbols)


def is_line_after_msgid(line):
    symbols = ['msgstr', '"']
    return any(line.startswith(symbol) for symbol in symbols)


def occurrence_to_reference(occurrence):
    """
    Converts an occurrence tuple to a reference line
    :param occurrence:
    :return:
    """
    return '#: ' + (f'{occurrence[0]}:{occurrence[1]}' if occurrence[1] else occurrence[0])


def msgstr_to_line(msgstr):
    return f'msgstr "{msgstr}"'


def filter_occurrences(occurrences, regex):
    """
    Returns occurrences that match the regex
    :param occurrences:
    :param regex:
    :return:
    """
    return [o for o in occurrences if re.search(regex, occurrence_to_reference(o))]


def find_po_files(path, regex='.'):
    result = []
    for root, dirs, files in os.walk(path):
        for file in files:
            absolute_path = os.path.join(str(root), file)
            if file.endswith('.po') and re.search(regex, absolute_path):
                result.append(absolute_path)
    return result


class POMergerEntry:
    """
    Encapsulates entries in a po file
    """

    def __init__(self, entry, source_path):
        self.entry = entry
        self.source_path = source_path

        self.lines = []
        self.occurrences = set(entry.occurrences)
        self.new_msgstr = None

    def __str__(self, sort_references=False):
        result = ''
        reference_index = 0
        were_references_added = was_new_msgstr_added = False
        references_lines = []
        added_occurrences = set()
        for line in self.lines:
            write_line = True
            if is_reference(line):
                occurrence = self.entry.occurrences[reference_index]
                if occurrence in self.occurrences and occurrence not in added_occurrences:
                    references_lines.append(line)
                reference_index += 1
                added_occurrences.add(occurrence)
                write_line = False
            elif is_line_after_references(line) and not were_references_added:
                for occurrence in self.added_occurrences:
                    references_lines.append(f'{occurrence_to_reference(occurrence)}\n')
                if sort_references:
                    references_lines.sort()
                result += ''.join(references_lines)
                were_references_added = True
            if is_line_after_msgid(line) and self.new_msgstr:
                write_line = False
                if not was_new_msgstr_added:
                    result += f'{msgstr_to_line(self.new_msgstr)}\n'
                    was_new_msgstr_added = True
            if write_line:
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
        return self.entry.msgid, (self.new_msgstr or self.entry.msgstr)

    def merge_occurrences(self, other):
        """
        Merge occurrences of current object with another POMergerEntry object (union on occurrences)
        :param other:
        :return:
        """
        self.occurrences = self.occurrences.union(other.occurrences)

    def match_occurrences(self, other, regex='.'):
        """
        Set occurrences of current object to match another POMergerEntry object's occurrences
        (occurrences matching regex only)
        :param other:
        :param regex:
        :return:
        """
        filtered_self_occurrences = set(filter_occurrences(self.occurrences, regex))
        self.occurrences = self.occurrences.union(other.occurrences) - (filtered_self_occurrences - other.occurrences)

    def references_match_regex(self, regex, match_empty=True):
        """
        Checks whether the entry matches the given regex
        If match_empty is True then entries with empty occurrence list will be matched
        :param regex:
        :param match_empty:
        :return:
        """
        occurrences = self.occurrences.union(self.entry.occurrences)
        return any(filter_occurrences(occurrences, regex)) or (match_empty and not self.entry.occurrences)

    def msgid_matches_regex(self, regex, match_empty=True):
        return bool(re.search(regex, self.entry.msgid)) or (match_empty and not self.entry.msgid)


class POMerger:
    def __init__(self, base_path, output_path, **kwargs):
        self.base_path = base_path
        self.output_path = output_path

        self.external_paths = kwargs.get('external_paths', [])
        self.exported_path = kwargs.get('exported_path', None)
        self.regex = kwargs.get('regex', '.')
        self.translations_paths = kwargs.get('translations_paths', [])
        self.translations_regex = kwargs.get('translations_regex', '.')
        self.translate_new_only = kwargs.get('translate_new_only', False)
        self.unmatch_references_regex = kwargs.get('unmatch_references_regex', None)
        self.unmatch_msgid_regex = kwargs.get('unmatch_msgid_regex', None)
        self.delete_references_regex = kwargs.get('delete_references_regex', None)
        self.delete_msgid_regex = kwargs.get('delete_msgid_regex', None)
        self.delete_matched_only = kwargs.get('delete_matched_only', False)
        self.all_references = kwargs.get('all_references', False)
        self.ignore_duplicates = kwargs.get('ignore_duplicates', False)
        self.verbose_log = kwargs.get('verbose_log', False)
        self.no_merge_suggestions = kwargs.get('no_merge_suggestions', False)
        self.sort_entries = kwargs.get('sort_entries', False)
        self.sort_references = kwargs.get('sort_references', False)
        self.summary_only = kwargs.get('summary_only', False)
        self.no_warnings = kwargs.get('no_warnings', False)

        self.entries = defaultdict(list)
        self.matched_msgids = set()
        self.output_entries = []

        self.preamble = ''
        self.added_entries, self.merged_entries, self.removed_entries = set(), set(), []
        self.lines_added = self.lines_removed = 0
        self.warnings = []

        self.parse_entries()
        self.add_base_entries()
        self.add_external_entries()

        if self.exported_path:
            # filter first to prevent resolving ambiguity for entries that are not in the exported file
            self.filter_not_in_exported()

        if not self.no_merge_suggestions:
            self.suggest_merge_same_msgid()

        if self.exported_path:
            self.add_exported_entries()

        if self.delete_msgid_regex:
            self.delete_msgids()
        if self.delete_references_regex:
            self.delete_references()

        self.filter_no_references()

        if self.translations_paths:
            self.suggest_translations()

        if self.sort_entries:
            self.output_entries.sort()

        self.calculate_statistics()
        self.add_extra_warnings()

    def parse_entries(self):
        """
        Parses entries from all paths into POMergerEntry object
        """
        unmatched_msgids = set()
        paths = [self.base_path] + self.external_paths + ([self.exported_path] if self.exported_path else [])
        for path in paths:
            for entry in pofile(path):
                merger_entry = POMergerEntry(entry, path)
                self.entries[path].append(merger_entry)

                msgid_unmatch = self.unmatch_msgid_regex and merger_entry.msgid_matches_regex(
                    self.unmatch_msgid_regex, match_empty=False
                )
                references_unmatch = self.unmatch_references_regex and merger_entry.references_match_regex(
                    self.unmatch_references_regex, match_empty=False
                )
                is_unmatched = entry.msgid in unmatched_msgids or msgid_unmatch or references_unmatch
                if merger_entry.references_match_regex(self.regex):
                    if is_unmatched:
                        unmatched_msgids.add(entry.msgid)
                    else:
                        self.matched_msgids.add(entry.msgid)
        for msgid in sorted(unmatched_msgids):
            self.warnings.append(f'The following msgid has been unmatched: {msgid}')
        self.parse_entries_lines()

    def parse_entries_lines(self):
        """
        Find the lines of each of the parsed entries from their files
        """
        for path, entries in self.entries.items():
            entry_by_linenum = {entry.entry.linenum: entry for entry in entries}
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

    def add_base_entries(self):
        added_entries = {}
        for base_entry in self.entries[self.base_path]:
            if base_entry in added_entries:
                added_entries[base_entry].merge_occurrences(base_entry)
                self.removed_entries.append((base_entry, 'Duplicate entry'))
            else:
                self.output_entries.append(base_entry)
                added_entries[base_entry] = base_entry

    def add_external_entries(self):
        added_entries = {e: e for e in self.output_entries}
        for path in self.external_paths:
            for external_entry in filter(lambda e: e.entry.msgid in self.matched_msgids, self.entries[path]):
                regex = self.regex if not self.all_references else '.'
                external_entry.occurrences = set(
                    filter_occurrences(external_entry.occurrences, regex)
                )
                if external_entry in added_entries:
                    added_entries[external_entry].merge_occurrences(external_entry)
                else:
                    self.output_entries.append(external_entry)
                    added_entries[external_entry] = external_entry

    def add_exported_entries(self):
        output_entries_by_msgid = defaultdict(list)
        for output_entry in self.output_entries:
            output_entries_by_msgid[output_entry.entry.msgid].append(output_entry)
        for exported_entry in filter(lambda e: e.entry.msgid in self.matched_msgids, self.entries[self.exported_path]):
            msgid = exported_entry.entry.msgid
            regex = self.regex if not self.all_references else '.'
            exported_entry.occurrences = set(
                filter_occurrences(exported_entry.occurrences, regex)
            )
            matching_entries = output_entries_by_msgid[msgid]
            if not matching_entries:
                self.output_entries.append(exported_entry)
            elif len(matching_entries) == 1:
                matching_entries[0].match_occurrences(exported_entry, regex)
            else:
                self.match_multiple_entries(exported_entry, matching_entries, regex)

    def match_multiple_entries(self, matcher_entry, matching_entries, regex):
        """
        Match an entry's occurrences with a list of other entries, give choice where to add each new occurrence if
        destination is ambiguous
        """
        ambiguous_occurrences = None
        for matching_entry in matching_entries:
            old_occurrences = matching_entry.occurrences
            matching_entry.match_occurrences(matcher_entry, regex)
            added_occurrences = matching_entry.occurrences - old_occurrences
            matching_entry.occurrences -= added_occurrences

            if ambiguous_occurrences is None:
                ambiguous_occurrences = added_occurrences
            else:
                ambiguous_occurrences = ambiguous_occurrences.intersection(added_occurrences)

        if self.ignore_duplicates and ambiguous_occurrences:
            self.warnings.append(
                f'Ignored ambiguous references for entries with duplicate msgids: \'{matcher_entry.entry.msgid}\'')
        else:
            for i, occurrence in enumerate(sorted(ambiguous_occurrences)):
                _, j = pick(
                    [e.entry.msgstr for e in matching_entries],
                    f'REFERENCE AMBIGUITY ({i + 1} of {len(ambiguous_occurrences)})\n\nDuplicate msgid found:'
                    f' \'{matcher_entry.entry.msgid}\'\nChoose a msgstr for the below reference:'
                    f'\n\n{occurrence_to_reference(occurrence)}',
                    indicator='=>'
                )
                matching_entries[j].occurrences.add(occurrence)

    def suggest_merge_same_msgid(self):
        """
        Suggest to merge an entry's occurrences with another entry and remove it if they have the same msgid
        """
        output_entries_by_msgid = defaultdict(list)
        for output_entry in self.output_entries:
            output_entries_by_msgid[output_entry.entry.msgid].append(output_entry)
        output_entries_by_msgid = {
            m: e for m, e in output_entries_by_msgid.items() if len(e) > 1 and m in self.matched_msgids
        }

        removed_entries = set()
        for i, (msgid, entries) in enumerate(output_entries_by_msgid.items()):
            remaining_entries = [e for e in entries]
            while len(remaining_entries) > 1:
                selected = pick(
                    [f'{e.entry.msgstr}' for e in remaining_entries],
                    f'ENTRY MERGE SUGGESTION ({i + 1} of {len(output_entries_by_msgid)})\n\nThe entries with'
                    f' the following msgstrs have the same msgid:\n\n\'{msgid}\'\n\nDo you want to merge any of them?'
                    f' Select the ones you want to be merged and removed and then select the entry to merge into LAST'
                    f'\n(press SPACE to mark, ENTER to continue/skip)',
                    indicator='=>', multiselect=True,
                )
                selected_indices = [j for _, j in selected]
                if not selected_indices:
                    break

                merge_into_entry = remaining_entries[selected_indices[-1]]
                for j in selected_indices[:-1]:
                    merger_entry = remaining_entries[j]
                    merge_into_entry.merge_occurrences(merger_entry)
                    removed_entries.add(merger_entry)
                    if merger_entry.source_path == self.base_path:
                        self.removed_entries.append((merger_entry, 'Merged with another duplicate msgid entry'))

                remaining_entries = [e for e in entries if e not in removed_entries]

        self.output_entries = [e for e in self.output_entries if e not in removed_entries]

    def filter_not_in_exported(self):
        matched_exported_msgids = {
            e.entry.msgid for e in self.entries[self.exported_path] if e.entry.msgid in self.matched_msgids
        }
        output_entries = []
        for output_entry in self.output_entries:
            msgid = output_entry.entry.msgid
            is_base_entry = output_entry.source_path == self.base_path
            is_matched = msgid in self.matched_msgids
            not_in_exported = (is_matched or not is_base_entry) and msgid not in matched_exported_msgids

            if not_in_exported:
                if is_base_entry:
                    self.removed_entries.append((output_entry, 'Not in exported file'))
            else:
                output_entries.append(output_entry)

        self.output_entries = output_entries

    def filter_no_references(self):
        output_entries = []
        for output_entry in self.output_entries:
            is_base_entry = output_entry.source_path == self.base_path
            no_references = len(output_entry.occurrences) == 0

            if no_references:
                if is_base_entry:
                    self.removed_entries.append((output_entry, 'No references'))
            else:
                output_entries.append(output_entry)

        self.output_entries = output_entries

    def delete_msgids(self):
        output_entries = []
        for output_entry in self.output_entries:
            is_base_entry = output_entry.source_path == self.base_path
            is_matched = not self.delete_matched_only or output_entry.entry.msgid in self.matched_msgids
            to_delete = is_matched and output_entry.msgid_matches_regex(self.delete_msgid_regex)

            if to_delete:
                if is_base_entry:
                    self.removed_entries.append((output_entry, 'Deleted'))
            else:
                output_entries.append(output_entry)

        self.output_entries = output_entries

    def delete_references(self):
        for output_entry in self.output_entries:
            is_matched = not self.delete_matched_only or output_entry.entry.msgid in self.matched_msgids
            if not is_matched:
                continue
            to_delete_references = set(filter_occurrences(output_entry.occurrences, self.delete_references_regex))
            output_entry.occurrences -= to_delete_references

    def calculate_statistics(self):
        for merger_entry, _ in self.removed_entries:
            self.lines_removed += len(merger_entry.lines)

        for output_entry in self.output_entries:
            if output_entry.source_path == self.base_path:
                lines_added = len(output_entry.added_occurrences)
                lines_removed = len(output_entry.removed_occurrences)
                self.lines_added += lines_added
                self.lines_removed += lines_removed
                if lines_added or lines_removed:
                    self.merged_entries.add(output_entry)
            else:
                self.added_entries.add(output_entry)
                self.lines_added += output_entry.__str__().count('\n')

    def add_extra_warnings(self):
        output_entries_by_msgstr = defaultdict(list)
        for output_entry in self.output_entries:
            output_entries_by_msgstr[output_entry.entry.msgstr].append(output_entry)
        for msgstr, entries in output_entries_by_msgstr.items():
            if len(entries) > 1 and any(e.entry.msgid in self.matched_msgids for e in entries):
                msgids = ', '.join([f'\'{e.entry.msgid}\'' for e in entries])
                self.warnings.append(f'Entries with the following msgids have the same msgstr \'{msgstr}\': {msgids}')

    def suggest_translations(self):
        entries = [e for e in self.output_entries if not self.translate_new_only or e.source_path != self.base_path]
        if not entries:
            return

        po_files = set()
        for path in self.translations_paths:
            po_files.update(find_po_files(path, self.translations_regex))

        suggested_msgstrs_by_msgid = {e.entry.msgid.strip().lower(): {e.entry.msgstr} for e in entries}
        for po_file in po_files:
            try:
                for entry in pofile(po_file):
                    msgid = entry.msgid.strip().lower()
                    if msgid in suggested_msgstrs_by_msgid:
                        suggested_msgstrs_by_msgid[msgid].add(entry.msgstr)
            except OSError:
                self.warnings.append(
                    f'The following translation file was partly processed due to a PO syntax error: {po_file}')

        suggested_msgstrs_by_entry = {}
        for merger_entry in entries:
            msgid = merger_entry.entry.msgid.strip().lower()
            if msgid in suggested_msgstrs_by_msgid and len(suggested_msgstrs_by_msgid[msgid]) > 1:
                suggested_msgstrs_by_entry[merger_entry] = suggested_msgstrs_by_msgid[msgid]

        for i, (merger_entry, suggested_msgstrs) in enumerate(suggested_msgstrs_by_entry.items()):
            suggestions = ([merger_entry.entry.msgstr]
                           + sorted([m for m in suggested_msgstrs if m != merger_entry.entry.msgstr]))
            _, j = pick(
                [f'{m} (Original)' if k == 0 else m for k, m in enumerate(suggestions)],
                f'TRANSLATION SUGGESTION ({i + 1} of {len(suggested_msgstrs_by_entry)})\n\n'
                f'The entry with following msgid:\n\n\'{merger_entry.entry.msgid}\'\n\nmay be translated as'
                f' one of the following:\n\n',
                indicator='=>'
            )
            if j != 0:
                merger_entry.new_msgstr = suggestions[j]

    def run(self):
        if not self.summary_only:
            for merger_entry, removal_reason in self.removed_entries:
                self.log_entry(merger_entry, removal_reason)
        with open(self.output_path, 'w', encoding='utf-8') as output_file:
            output_file.write(self.preamble)
            for i, entry in enumerate(self.output_entries):
                entry_string = entry.__str__(sort_references=self.sort_references)

                # fix entries from other files than base getting concatenated on same line
                if i == len(self.output_entries) - 1:
                    entry_string = entry_string.rstrip('\n')
                elif not entry_string.endswith('\n\n'):
                    entry_string += '\n\n'
                output_file.write(entry_string)
                if not self.summary_only:
                    self.log_entry(entry)

        if not self.summary_only and not self.no_warnings:
            for warning in self.warnings:
                print(colored(warning, 'yellow'))
        if self.lines_added == self.lines_removed == 0:
            print('No changes done, original file is identical to output file')
        else:
            self.log_statistics()

    def log_entry(self, merger_entry, removal_reason=None):
        state = 'Unaffected'
        linenum = str(merger_entry.entry.linenum) if merger_entry.source_path == self.base_path else 'NEW'
        msgid = colored(merger_entry.entry.msgid, 'light_grey')
        comment = ''
        log_entry = True

        if merger_entry.source_path == self.base_path:
            if removal_reason:
                state = colored('Removed', 'red')
                linenum = colored(linenum, 'red')
                comment = f' ({colored(removal_reason, "red")})'
            elif merger_entry in self.merged_entries:
                state = colored('Modified', 'cyan')
                linenum = colored(linenum, 'cyan')

                added = colored(f'Added {len(merger_entry.added_occurrences)}', 'green')
                removed = colored(f'removed {len(merger_entry.removed_occurrences)}', 'red')
                comment = f' ({added} and {removed} references)'
            elif not self.verbose_log:
                log_entry = False
        else:
            state = colored('Added', 'green')
            linenum = colored(linenum, 'green')
            if merger_entry.source_path == self.exported_path:
                comment = 'Exported file'
            else:
                if len(self.external_paths) == 1:
                    comment = 'External file'
                else:
                    comment = f'External file #{self.external_paths.index(merger_entry.source_path) + 1}'
            comment = f' ({colored(comment, "green")})'

        if not removal_reason and merger_entry.new_msgstr:
            comment += f' ({colored("Translation updated", "green")})'

        if log_entry:
            print(f'{state} {linenum}{comment}: {msgid}')

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
        print('Added {}, merged {} and removed {}'.format(*entries))
        print('Added {} and removed {}'.format(*lines))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--base-path', required=True, help='Base file path')
    parser.add_argument('-o', '--output-path', required=True, help='Output file path')
    parser.add_argument('-m', '--external-paths', nargs='+', help='External files paths', default=[])
    parser.add_argument('-e', '--exported-path', help='Exported file path')
    parser.add_argument('-r', '--regex',
                        help='Match only entries that have references matching this regex. Default: all', default='.')
    parser.add_argument('-t', '--translations-paths', nargs='+',
                        help='If any directory path is passed here then all the entries in all PO files'
                             ' in the sub-folders of that directory will be used as translation suggestions'
                             ' for the entries of the output file if the their msgids match', default=[])
    parser.add_argument('-T', '--translations-regex',
                        help='Match only translation files that have absolute paths matching this regex', default='.')
    parser.add_argument('-n', '--translate-new-only', action='store_true',
                        help='Suggest translations for added (new) entries only')
    parser.add_argument('-u', '--unmatch-references-regex',
                        help='Entries that have references matching this regex will never be matched')
    parser.add_argument('-U', '--unmatch-msgid-regex',
                        help='Entries that have msgid matching this regex will never be matched')
    parser.add_argument('-d', '--delete-references-regex',
                        help='Delete reference lines matching this regex')
    parser.add_argument('-D', '--delete-msgid-regex',
                        help='Delete entries with msgid matching this regex')
    parser.add_argument('--delete-matched-only', action='store_true',
                        help='Delete entries with msgid matching this regex')
    parser.add_argument('-a', '--all-references', action='store_true',
                        help='If this flag is passed then all references of each matched entry will be matched')
    parser.add_argument('-i', '--ignore-duplicates', action='store_true',
                        help='If this flag is passed then no new references will be added'
                             ' to entries with duplicate msgids')
    parser.add_argument('-v', '--verbose-log', action='store_true',
                        help='If this flag is passed then extra information is logged to the console')
    parser.add_argument('--no-merge-suggestions', action='store_true',
                        help='If this flag is passed then no suggestions for merging entries are shown'
                             ' (all entries are kept)')
    parser.add_argument('-S', '--sort-entries', action='store_true',
                        help='If this flag is passed then the entries are sorted in the output file according'
                             ' to msgid and msgstr')
    parser.add_argument('-s', '--sort-references', action='store_true',
                        help='If this flag is passed then the references of each entry are sorted in the output file')
    parser.add_argument('--summary-only', action='store_true',
                        help='Log only the summary of what has been done')
    parser.add_argument('--no-warnings', action='store_true',
                        help='Do not log any warning')

    po_merger = POMerger(**vars(parser.parse_args()))
    po_merger.run()
