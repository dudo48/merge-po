"""
The happiness of most people is not ruined by great catastrophes or fatal errors,
but by the repetition of slowly destructive little things.
    - Ernest Dimnet
"""

import argparse
from enum import Enum
import glob
import re
from typing import Union

from pick import pick
from polib import pofile, POEntry
from tabulate import tabulate


class MergePOEntrySource(Enum):
    BASE = 0
    EXTERNAL = 1
    EXPORTED = 2


class MergePOEntry:
    """
    Encapsulates entries in a PO file
    """

    def __init__(self, entry: POEntry, source: MergePOEntrySource, source_path: str):
        self.entry = entry
        self.source = source
        self.original_occurrences = [occurrence for occurrence in entry.occurrences]
        self.original_msgstr = entry.msgstr
        self.removal_reason: Union[str, None] = None
        self.source_path = source_path

    def __key(self):
        return self.entry.msgid, self.entry.msgstr, self.source_path, self.entry.linenum

    def __repr__(self):
        return str(self.__key())

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other: "MergePOEntry"):
        return self.__key() == other.__key()

    def __lt__(self, other: "MergePOEntry"):
        return self.__key() < other.__key()

    # functions to check if a specific part of the entry matches a regex
    def _occurrences_match(self, regex: str):
        matched_occurrences = MergePOEntry.filter_occurrences(self.entry.occurrences, regex)

        # empty occurrences are always matched
        return matched_occurrences or not self.entry.occurrences

    def _msgid_matches(self, regex: str):
        return bool(re.search(regex, self.entry.msgid))

    def _msgstr_matches(self, regex: str):
        return bool(re.search(regex, self.entry.msgstr))

    def matches(self, regex: str):
        """
        Whether the entry matches a regex
        """
        return self._occurrences_match(regex) or self._msgid_matches(regex) or self._msgstr_matches(regex)

    def remove_duplicate_occurrences(self):
        # used dict keys to maintain list order
        self.entry.occurrences = list(dict.fromkeys(self.entry.occurrences))

    def merge_occurrences(self, other: "MergePOEntry"):
        """
        Union occurrences with another entry
        """
        occurrences_set = set(self.entry.occurrences)
        self.entry.occurrences.extend([o for o in other.entry.occurrences if o not in occurrences_set])

    def match_occurrences(self, other: "MergePOEntry"):
        """
        Set entry's occurrences to match occurrences of another entry
        """
        self.entry.occurrences = other.entry.occurrences.copy()

    def is_base_entry(self):
        return self.source == MergePOEntrySource.BASE

    def is_external_entry(self):
        return self.source == MergePOEntrySource.EXTERNAL

    def is_exported_entry(self):
        return self.source == MergePOEntrySource.EXPORTED

    def describe_changes(self):
        changes = []

        # Tell if file was not originally in the base file
        if self.is_external_entry():
            changes.append("Added from external file")
        if self.is_exported_entry():
            changes.append("Added from exported file")

        # Calculate added and removed occurrences
        occurrences_set = set(self.entry.occurrences)
        original_occurrences_set = set(self.original_occurrences)

        added_occurrences = [o for o in self.entry.occurrences if o not in original_occurrences_set]
        removed_occurrences = [o for o in self.original_occurrences if o not in occurrences_set]

        if added_occurrences or removed_occurrences:
            changes.append(f"Added {len(added_occurrences)} and removed {len(removed_occurrences)} references")

        # Detect changed translation
        if self.entry.msgstr != self.original_msgstr:
            changes.append(f"Updated msgstr")

        return ", ".join(changes) or None

    @staticmethod
    def match_occurrences_multi(source: "MergePOEntry", destinations: "list[MergePOEntry]"):
        """
        Set destination entries to match the source entry's occurrences, giving choice in case of ambiguity
        """
        if len(destinations) == 1:
            return destinations[0].match_occurrences(source)

        # ambiguous occurrences are occurrences which are present in source but not present in any destination entry
        # therefore, they're ambiguous because it is not clear which entry should be their destination
        source_occurrences: set[tuple[str]] = set(source.entry.occurrences)
        unambiguous_occurrences: set[tuple[str]] = set()
        for entry in destinations:
            new_occurrences: list[tuple[str]] = []
            for occurrence in entry.entry.occurrences:
                if occurrence in source_occurrences:
                    new_occurrences.append(occurrence)
                    unambiguous_occurrences.add(occurrence)
            entry.entry.occurrences = new_occurrences

        ambiguous_occurrences = [o for o in source.entry.occurrences if o not in unambiguous_occurrences]
        for i, occurrence in enumerate(sorted(ambiguous_occurrences)):
            _, j = pick(
                [entry.entry.msgstr for entry in destinations],
                f"REFERENCE AMBIGUITY ({i + 1} of {len(ambiguous_occurrences)})\n\nDuplicate msgid found: '{source.entry.msgid}'\nChoose a msgstr for the below reference:\n\n{occurrence[0]}",
                indicator="=>",
            )
            if isinstance(j, int):  # added this condition to suppress pick return type warning
                destinations[j].entry.occurrences.append(occurrence)

    @staticmethod
    def filter_occurrences(occurrences: "list[tuple[str, int]]", regex: str):
        return [o for o in occurrences if re.search(regex, o[0])]

    @staticmethod
    def get_normalized_msgid(msgid: str):
        return msgid.strip().lower()


class MergePO:
    def __init__(
        self,
        base_path: str,
        output_path: Union[str, None],
        external_paths: "list[str]",
        exported_path: Union[str, None],
        regex: str,
        sort_entries: bool,
        sort_references: bool,
        interactive_translation: bool,
        translations_glob: Union[str, None],
        verbose: bool,
    ):
        self.base_path = base_path
        self.base_pofile = pofile(self.base_path)
        self.output_path = output_path or base_path
        self.external_paths = external_paths
        self.exported_path = exported_path

        self.regex = regex
        self.sort_entries = sort_entries
        self.sort_references = sort_references
        self.translations_glob = translations_glob
        self.interactive_translation = interactive_translation
        self.verbose = verbose

        self.entries: list[MergePOEntry] = []
        self.output_entries: list[MergePOEntry] = []

        self.matched_msgids: set[str] = set()

        self.run()
        self.save_output_file()
        self.describe_changes()

    def run(self):
        self.find_entries()
        self.find_matched_msgids()
        self.add_base_entries()
        self.add_external_entries()
        self.filter_duplicates()

        if self.exported_path:
            # filter first to prevent resolving ambiguity for entries that are not in the exported file
            self.filter_not_in_exported()

        self.suggest_merge_same_msgid()

        if self.exported_path:
            self.add_exported_entries()

        self.filter_no_occurrences()

        if self.translations_glob:
            self.suggest_translations()

            # filter duplicates again because some msgstrs may have been changed to be same as other entries
            self.filter_duplicates()

        if self.interactive_translation:
            self.translate_interactively()
            self.filter_duplicates()

        self.filter_duplicate_occurrences()

        if self.sort_entries:
            self.output_entries.sort()

        if self.sort_references:
            self.sort_occurrences()

    def _is_matched_entry(self, entry: MergePOEntry):
        return entry.entry.msgid in self.matched_msgids

    def _group_output_entries_by_msgid(self):
        result: dict[str, list[MergePOEntry]] = {}
        for entry in self.output_entries:
            if entry.entry.msgid in result:
                result[entry.entry.msgid].append(entry)
            else:
                result[entry.entry.msgid] = [entry]
        return result

    def _group_output_entries_by_msgstr(self):
        result: dict[str, list[MergePOEntry]] = {}
        for entry in self.output_entries:
            if entry.entry.msgstr in result:
                result[entry.entry.msgstr].append(entry)
            else:
                result[entry.entry.msgstr] = [entry]
        return result

    def _group_output_entries_by_msgid_msgstr(self):
        result: dict[tuple[str], list[MergePOEntry]] = {}
        for entry in self.output_entries:
            key = (entry.entry.msgid, entry.entry.msgstr)
            if key in result:
                result[key].append(entry)
            else:
                result[key] = [entry]
        return result

    def find_entries(self):
        """
        Find and convert all entries from all input files into entry objects
        """
        for entry in self.base_pofile:
            self.entries.append(MergePOEntry(entry, MergePOEntrySource.BASE, self.base_path))

        for external_path in self.external_paths:
            for entry in pofile(external_path):
                self.entries.append(MergePOEntry(entry, MergePOEntrySource.EXTERNAL, external_path))

        if self.exported_path:
            for entry in pofile(self.exported_path):
                self.entries.append(MergePOEntry(entry, MergePOEntrySource.EXPORTED, self.exported_path))

    def find_matched_msgids(self):
        for entry in self.entries:
            if entry.matches(self.regex):
                self.matched_msgids.add(entry.entry.msgid)

    def add_base_entries(self):
        for entry in self.entries:
            if entry.is_base_entry():
                self.output_entries.append(entry)

    def add_external_entries(self):
        for entry in self.entries:
            if entry.is_external_entry() and self._is_matched_entry(entry):
                self.output_entries.append(entry)

    def add_exported_entries(self):
        entries_by_msgid = self._group_output_entries_by_msgid()
        for entry in self.entries:
            if entry.is_exported_entry() and self._is_matched_entry(entry):
                matched_output_entries = entries_by_msgid.get(entry.entry.msgid, [])
                if matched_output_entries:
                    MergePOEntry.match_occurrences_multi(entry, matched_output_entries)
                else:
                    self.output_entries.append(entry)

    def filter_duplicates(self):
        """
        Filter out entries which are duplicate in both msgid and msgstr
        """
        output_entries: list[MergePOEntry] = []
        added_entries: dict[tuple[str], MergePOEntry] = {}
        for entry in self.output_entries:
            key = (entry.entry.msgid, entry.entry.msgstr)
            if not self._is_matched_entry(entry) or key not in added_entries:
                output_entries.append(entry)
                added_entries[key] = entry
            else:
                added_entries[key].merge_occurrences(entry)
                entry.removal_reason = "Duplicate entry"
        self.output_entries = output_entries

    def filter_duplicate_occurrences(self):
        """
        Filter out duplicate occurrences for the same entry
        """
        for entry in self.output_entries:
            if self._is_matched_entry(entry):
                entry.remove_duplicate_occurrences()

    def filter_not_in_exported(self):
        """
        Filter out entries with msgids not present in exported file
        """
        exported_matched_msgids: set[str] = set()
        for entry in self.entries:
            if entry.is_exported_entry() and self._is_matched_entry(entry):
                exported_matched_msgids.add(entry.entry.msgid)

        output_entries = []
        for entry in self.output_entries:
            if not self._is_matched_entry(entry) or entry.entry.msgid in exported_matched_msgids:
                output_entries.append(entry)
            else:
                entry.removal_reason = "Not in exported file"
        self.output_entries = output_entries

    def filter_no_occurrences(self):
        """
        Filter out entries with empty occurrences list
        """
        output_entries = []
        for entry in self.output_entries:
            if not self._is_matched_entry(entry) or entry.entry.occurrences:
                output_entries.append(entry)
            else:
                entry.removal_reason = "No references"
        self.output_entries = output_entries

    def suggest_merge_same_msgid(self):
        """
        Suggest to merge occurrences of entries with same msgids
        """
        entries_by_msgid = {}
        for msgid, entries in self._group_output_entries_by_msgid().items():
            matched_entries = [entry for entry in entries if self._is_matched_entry(entry)]
            if len(matched_entries) > 1:
                entries_by_msgid[msgid] = matched_entries

        removed_entries: set[MergePOEntry] = set()
        for i, (msgid, entries) in enumerate(entries_by_msgid.items()):
            while len(entries) > 1:
                selected = pick(
                    [f"{entry.entry.msgstr}" for entry in entries],
                    f"ENTRY MERGE SUGGESTION ({i + 1} of {len(entries_by_msgid)})\n\nThe entries with the following msgstrs have the same msgid:\n\n'{msgid}'\n\nDo you want to merge any of them? Select the ones you want to be merged and removed and then select the entry to merge into LAST\nor leave the selection empty to stop merging for this msgid\n(press SPACE to mark, ENTER to continue/skip)",
                    indicator="=>",
                    multiselect=True,
                )
                selected_indices = []
                if isinstance(selected, list):
                    selected_indices = [j for _, j in selected]
                if not selected_indices:
                    break

                removed_indices: set[int] = set()
                destination = entries[selected_indices[-1]]
                for j in selected_indices[:-1]:
                    entry = entries[j]
                    destination.merge_occurrences(entry)
                    removed_indices.add(j)
                    removed_entries.add(entry)
                    entry.removal_reason = "Merged with another entry"
                entries = [entry for j, entry in enumerate(entries) if j not in removed_indices]
        self.output_entries = [entry for entry in self.output_entries if entry not in removed_entries]

    def suggest_translations(self):
        matched_entries = [entry for entry in self.output_entries if self._is_matched_entry(entry)]
        if not matched_entries or not self.translations_glob:
            return

        # group matched entries by normalized msgid
        entries_by_normalized_msgid: dict[str, list[MergePOEntry]] = {}
        for entry in matched_entries:
            normalized_msgid = MergePOEntry.get_normalized_msgid(entry.entry.msgid)
            if normalized_msgid in entries_by_normalized_msgid:
                entries_by_normalized_msgid[normalized_msgid].append(entry)
            else:
                entries_by_normalized_msgid[normalized_msgid] = [entry]
        suggested_msgstrs_by_msgid: dict[str, list[str]] = {
            msgid: [] for msgid in entries_by_normalized_msgid
        }

        # find PO files
        po_files_paths = glob.glob(self.translations_glob, recursive=True)
        for path in po_files_paths:
            try:
                for entry in pofile(path):
                    normalized_msgid = MergePOEntry.get_normalized_msgid(entry.msgid)
                    if normalized_msgid in suggested_msgstrs_by_msgid:
                        suggested_msgstrs_by_msgid[normalized_msgid].append(entry.msgstr)
            except OSError:
                # PO syntax error in the file raised an exception
                pass

        # filter out repeated suggestions and suggestions equal to original msgstr
        suggestions_by_entry: dict[MergePOEntry, list[str]] = {}
        for msgid, suggestions in suggested_msgstrs_by_msgid.items():
            unique_suggestions: list[str] = []
            added_suggestions = {entry.entry.msgstr for entry in entries_by_normalized_msgid[msgid]}
            for msgstr in suggestions:
                if msgstr not in added_suggestions:
                    unique_suggestions.append(msgstr)
                    added_suggestions.add(msgstr)
            if unique_suggestions:
                for entry in entries_by_normalized_msgid[msgid]:
                    suggestions_by_entry[entry] = unique_suggestions

        for i, (entry, suggestions) in enumerate(suggestions_by_entry.items()):
            choices = [f"'{entry.entry.msgstr} (Original)'"] + [f"'{msgstr}'" for msgstr in suggestions]
            _, j = pick(
                choices,
                f"TRANSLATION SUGGESTION ({i + 1} of {len(suggestions_by_entry)})\n\nThe entry with following msgid:\n\n'{entry.entry.msgid}'\n\nmay be translated as one of the following:\n\n",
                indicator="=>",
            )
            if isinstance(j, int) and j != 0:
                entry.entry.msgstr = suggestions[j - 1]

    def translate_interactively(self):
        matched_entries = [entry for entry in self.output_entries if self._is_matched_entry(entry)]
        for i, entry in enumerate(matched_entries):
            print(
                f"INTERACTIVE TRANSLATION ({i + 1} of {len(matched_entries)})\n\nEnter translation for the entry with the below msgid and msgstr or leave the input empty to leave its msgstr as it is\n\n'{entry.entry.msgid}' -> '{entry.entry.msgstr}'\n\n"
            )
            new_msgstr = input(": ")
            if new_msgstr:
                entry.entry.msgstr = new_msgstr
            print("\n")

    def sort_occurrences(self):
        for entry in self.output_entries:
            if self._is_matched_entry(entry):
                entry.entry.occurrences.sort()

    def describe_changes(self):
        if self.sort_entries:
            print(f"Sorted entries")
        if self.sort_references:
            print(f"Sorted references")

        added_entries_count = modified_entries_count = removed_entries_count = 0

        # Log output entries table
        data = []
        for entry in self.output_entries:
            changes = entry.describe_changes()
            if changes:
                if not entry.is_base_entry():
                    added_entries_count += 1
                else:
                    modified_entries_count += 1
            if self.verbose or changes:
                data.append([entry.entry.msgid, entry.entry.msgstr, entry.describe_changes()])

        headers = ["Msgid", "Msgstr", "Changes"]
        maxcolwidths = [32, 32, 32]

        if data:
            print("[Output file entries]")
            print(tabulate(data, headers=headers, maxcolwidths=maxcolwidths, tablefmt="simple_grid", showindex=True))
            print()

        # Log removed entries table
        data = []
        for entry in self.entries:
            if entry.removal_reason and entry.is_base_entry():
                removed_entries_count += 1
                data.append([entry.entry.msgid, entry.entry.msgstr, entry.removal_reason])

        headers = ["Msgid", "Msgstr", "Removal Reason"]
        maxcolwidths = [32, 32, 32]

        if data:
            print("[Removed entries]")
            print(tabulate(data, headers=headers, maxcolwidths=maxcolwidths, tablefmt="simple_grid", showindex=True))
            print()

        # Log repeated msgstrs
        data = [
            [msgstr, len(entries)]
            for msgstr, entries in self._group_output_entries_by_msgstr().items()
            if len(entries) > 1
        ]
        data.sort(key=lambda e: e[1], reverse=True)

        headers = ["Msgstr", "Frequency"]
        maxcolwidths = [64, 32]

        if data:
            print("[Repeated Msgstrs]")
            print(tabulate(data, headers=headers, maxcolwidths=maxcolwidths, tablefmt="simple_grid"))
            print()

        # Log summary
        if added_entries_count or modified_entries_count or removed_entries_count:
            print(
                f"Added {added_entries_count}, modified {modified_entries_count} and removed {removed_entries_count} entries"
            )
        else:
            print("No changes from base file")

    def save_output_file(self):
        output_file = self.base_pofile
        output_file.clear()
        output_file.extend([entry.entry for entry in self.output_entries])
        output_file.save(self.output_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--base-path", required=True, help="Base file path")
    parser.add_argument(
        "-o", "--output-path", help="Output file path, if not given defaults to base path (replaces original file)"
    )
    parser.add_argument("-x", "--external-paths", nargs="+", help="External files paths", default=[])
    parser.add_argument("-e", "--exported-path", help="Exported file path")
    parser.add_argument(
        "-r", "--regex", help="Match only entries that have references matching this regex. Default: all", default="."
    )
    parser.add_argument(
        "-S",
        "--sort-entries",
        action="store_true",
        help="If this flag is passed then the entries are sorted in the output file according" " to msgid and msgstr",
    )
    parser.add_argument(
        "-s",
        "--sort-references",
        action="store_true",
        help="If this flag is passed then the references of each entry are sorted in the output file",
    )
    parser.add_argument(
        "-t", "--translations-glob", help="Suggest translations for matched entries from PO files matching glob pattern"
    )
    parser.add_argument(
        "-i", "--interactive-translation", action="store_true", help="Interactively translate matched entries"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Log more information")

    MergePO(**vars(parser.parse_args()))
