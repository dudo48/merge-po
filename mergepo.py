"""
The happiness of most people is not ruined by great catastrophes or fatal errors,
but by the repetition of slowly destructive little things.
    - Ernest Dimnet
"""

import argparse
import glob
import hashlib
import os
import pickle
import re
from enum import Enum
from typing import Tuple, TypeVar, Union, cast

from pick import PICK_RETURN_T, pick
from polib import POEntry, pofile
from tabulate import tabulate

MERGEPO_PATH = os.path.dirname(os.path.abspath(__file__))
PERSISTENT_DATA_PATH = os.path.join(MERGEPO_PATH, '.persistent')

T = TypeVar('T')
EXCLUDED_ENTRIES_FILE_NAME = 'excluded'
SUGGESTED_MERGES_FILE_NAME = 'suggested_merges'
PICK_INDICATOR = '=>'


def load_persistent_data(path: str) -> Union[T, None]: # type: ignore
    try:
        with open(path, 'rb') as file:
            return pickle.load(file)
    except FileNotFoundError:
        pass
    return None

def save_persistent_data(path: str, data: object):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as file:
        return pickle.dump(data, file)


class MergePOEntrySource(Enum):
    BASE = 0
    EXTERNAL = 1
    EXPORTED = 2


class MergePOEntry:
    def __init__(self, entry: POEntry, source: MergePOEntrySource):
        self.entry = entry
        self.source = source
        self.original_occurrences = [occurrence for occurrence in entry.occurrences]
        self.original_msgstr = entry.msgstr
        self.removal_reason: Union[str, None] = None

    def __key(self):
        return self.entry.msgid, self.entry.msgstr

    def __repr__(self):
        return f"MergePOEntry({repr(self.entry.msgid)}, {repr(self.entry.msgstr)})"

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

    def filter_duplicate_occurrences(self):
        # used dict keys to maintain list order
        self.entry.occurrences = list(dict.fromkeys(self.entry.occurrences))

    def merge_occurrences(self, other: "MergePOEntry"):
        """
        Union occurrences with another entry
        """
        self.entry.occurrences.extend(o for o in other.entry.occurrences if o not in set(self.entry.occurrences))

    def match_occurrences(self, other: "MergePOEntry"):
        """
        Set entry's occurrences to match occurrences of another entry
        """
        self.entry.occurrences = [o for o in self.entry.occurrences if o in set(other.entry.occurrences)]
        self.entry.occurrences.extend(o for o in other.entry.occurrences if o not in set(self.entry.occurrences))

    def is_base_entry(self):
        return self.source == MergePOEntrySource.BASE

    def is_external_entry(self):
        return self.source == MergePOEntrySource.EXTERNAL

    def is_exported_entry(self):
        return self.source == MergePOEntrySource.EXPORTED

    def describe_changes(self):
        changes: list[str] = []

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

        return ", ".join(changes)

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
            options = [repr(entry.entry.msgstr) for entry in destinations]
            title = f"REFERENCE AMBIGUITY ({i + 1} of {len(ambiguous_occurrences)})\n\nDuplicate msgid found: {repr(source.entry.msgid)}\nChoose a msgstr for the below reference:\n\n{occurrence[0]}"
            _, j = cast(PICK_RETURN_T[str], pick(options=options, title=title, indicator=PICK_INDICATOR))
            destinations[j].entry.occurrences.append(occurrence)

    @staticmethod
    def filter_occurrences(occurrences: "list[tuple[str, str]]", regex: str):
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
        exclude: bool,
        unexclude: bool,
        reset_excluded: bool,
        confirm: bool,
        reset_suggested_merges: bool
    ):
        self.base_path = os.path.abspath(base_path)
        self.base_pofile = pofile(self.base_path)
        self.base_file_identifier = hashlib.sha1(
            pickle.dumps((self.base_pofile.header, str(self.base_pofile.metadata_as_entry())))
        ).hexdigest()

        self.output_path = os.path.abspath(output_path or base_path)
        self.external_paths = [os.path.abspath(path) for path in external_paths]
        self.exported_path = exported_path and os.path.abspath(exported_path)

        self.persistent_data_path = os.path.join(PERSISTENT_DATA_PATH, self.base_file_identifier)
        self.excluded_file_path = os.path.join(self.persistent_data_path, EXCLUDED_ENTRIES_FILE_NAME)
        self.suggested_merges_file_path = os.path.join(self.persistent_data_path, SUGGESTED_MERGES_FILE_NAME)

        self.regex = regex
        self.sort_entries = sort_entries
        self.sort_references = sort_references
        self.translations_glob = translations_glob
        self.interactive_translation = interactive_translation
        self.verbose = verbose
        self.exclude = exclude
        self.unexclude = unexclude
        self.reset_excluded = reset_excluded
        self.confirm = confirm
        self.reset_suggested_merges = reset_suggested_merges

        self.entries: list[MergePOEntry] = []
        self.output_entries: list[MergePOEntry] = []
        self.matched_msgids: set[str] = set()

        self.excluded_msgids: "set[str]" = load_persistent_data(self.excluded_file_path) or set()
        self.suggested_merges: "dict[str, set[str]]" = load_persistent_data(self.suggested_merges_file_path) or dict()

        self.run()

        save_persistent_data(self.excluded_file_path, self.excluded_msgids)
        save_persistent_data(self.suggested_merges_file_path, self.suggested_merges)

        self.save_output_file()
        self.describe_changes()

    def run(self):
        self.find_entries()
        self.find_matched_msgids()
        self.add_base_entries()
        self.add_external_entries()
        self.filter_duplicates()
        if self.exported_path:
            self.add_exported_entries()
            self.filter_not_in_exported()

        if self.reset_excluded:
            self.excluded_msgids.clear()

        if self.unexclude:
            self.unexclude_entries()

        if self.exclude:
            # filter before adding new excluded entries and after
            self.filter_excluded_entries()
            self.exclude_entries()
        self.filter_excluded_entries()

        if self.reset_suggested_merges:
            self.suggested_merges.clear()

        self.suggest_merge_same_msgid()
        self.filter_no_occurrences()
        self.filter_duplicate_occurrences()

        if self.confirm:
            self.confirm_new_entries()

        if self.translations_glob:
            self.suggest_translations()

            # filter duplicates again because some msgstrs may have been changed to be same as other entries
            self.filter_duplicates()

        if self.interactive_translation:
            self.translate_interactively()
            self.filter_duplicates()

        if self.sort_entries:
            self.output_entries.sort()

        if self.sort_references:
            self.sort_occurrences()

    def _is_matched_entry(self, entry: MergePOEntry):
        return entry.entry.msgid in self.matched_msgids

    def _is_excluded_entry(self, entry: MergePOEntry):
        return entry.entry.msgid in self.excluded_msgids

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
            self.entries.append(MergePOEntry(entry, MergePOEntrySource.BASE))

        for external_path in self.external_paths:
            for entry in pofile(external_path):
                self.entries.append(MergePOEntry(entry, MergePOEntrySource.EXTERNAL))

        if self.exported_path:
            for entry in pofile(self.exported_path):
                self.entries.append(MergePOEntry(entry, MergePOEntrySource.EXPORTED))

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
            if self._is_matched_entry(entry) and key in added_entries:
                added_entries[key].merge_occurrences(entry)
                entry.removal_reason = "Duplicate entry"
            else:
                output_entries.append(entry)
                added_entries[key] = entry
        self.output_entries = output_entries

    def filter_duplicate_occurrences(self):
        """
        Filter out duplicate occurrences for the same entry
        """
        for entry in self.output_entries:
            if self._is_matched_entry(entry):
                entry.filter_duplicate_occurrences()

    def filter_not_in_exported(self):
        """
        Filter out entries with msgids not present in exported file
        """
        exported_matched_msgids: set[str] = set()
        for entry in self.entries:
            if entry.is_exported_entry() and self._is_matched_entry(entry):
                exported_matched_msgids.add(entry.entry.msgid)

        output_entries: list[MergePOEntry] = []
        for entry in self.output_entries:
            if self._is_matched_entry(entry) and entry.entry.msgid not in exported_matched_msgids:
                entry.removal_reason = "Not in exported file"
            else:
                output_entries.append(entry)
        self.output_entries = output_entries

    def filter_no_occurrences(self):
        """
        Filter out entries with empty occurrences list
        """
        output_entries: list[MergePOEntry] = []
        for entry in self.output_entries:
            if self._is_matched_entry(entry) and not entry.entry.occurrences:
                entry.removal_reason = "No references"
            else:
                output_entries.append(entry)
        self.output_entries = output_entries

    def filter_excluded_entries(self):
        """
        Filter out entries which were previously excluded
        """
        output_entries: list[MergePOEntry] = []
        for entry in self.output_entries:
            if self._is_excluded_entry(entry):
                entry.removal_reason = "Excluded entry"
            else:
                output_entries.append(entry)
        self.output_entries = output_entries

    def suggest_merge_same_msgid(self):
        """
        Suggest to merge occurrences of entries with same msgids
        """
        entries_by_msgid: dict[str, list[MergePOEntry]] = {}
        for msgid, entries in self._group_output_entries_by_msgid().items():
            matched_entries = [entry for entry in entries if self._is_matched_entry(entry)]
            msgstr_set = {entry.entry.msgstr for entry in matched_entries}
            if len(matched_entries) > 1 and self.suggested_merges.get(msgid, set()) != msgstr_set:
                entries_by_msgid[msgid] = matched_entries

        removed_entries: set[MergePOEntry] = set()
        for i, (msgid, entries) in enumerate(entries_by_msgid.items()):
            while len(entries) > 1:
                options = [repr(entry.entry.msgstr) for entry in entries]
                title = f"ENTRY MERGE SUGGESTION ({i + 1} of {len(entries_by_msgid)})\n\nThe entries with the following msgstrs have the same msgid:\n\n'{msgid}'\n\nDo you want to merge any of them? Select the ones you want to be merged and removed and then select the entry to merge into LAST\nor leave the selection empty to stop merging for this msgid\n(press SPACE to mark, ENTER to continue/skip)"
                selected = cast(
                    "list[PICK_RETURN_T[str]]",
                    pick(options=options, title=title, indicator=PICK_INDICATOR, multiselect=True)
                )
                selected_indices = [j for _, j in selected]
                if not selected_indices:
                    self.suggested_merges[msgid] = {entry.entry.msgstr for entry in entries}
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

    def exclude_entries(self):
        """
        Interactively exclude certain entries from being added to the output file.
        The excluded entries persist between program runs.
        Excluded entries are always excluded regardless of whether or not they are matched.
        """
        options = [repr(entry.entry.msgid) for entry in self.output_entries]
        title = f"ENTRY EXCLUSION\n\nSelect msgids of entries that you want to exclude from this file\n\nThe selected entries will be removed from and never added to the output file\nin further runs of the program for the same base file"
        selected = cast(
            "list[PICK_RETURN_T[str]]",
            pick(options=options, title=title, indicator=PICK_INDICATOR, multiselect=True)
        )

        for _, i in selected:
            self.excluded_msgids.add(self.output_entries[i].entry.msgid)

    def unexclude_entries(self):
        """
        Unexclude entries that were previously excluded
        """
        if not self.excluded_msgids:
            return

        excluded_msgids = sorted(self.excluded_msgids)
        options = [repr(msgid) for msgid in excluded_msgids]
        title = f"ENTRY UNEXCLUSION\n\nSelect msgids of entries that you want to unexclude for this file"
        selected = cast(
            "list[PICK_RETURN_T[str]]",
            pick(options=options, title=title, indicator=PICK_INDICATOR, multiselect=True)
        )

        for _, i in selected:
            self.excluded_msgids.remove(excluded_msgids[i])

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
        suggested_msgstrs_by_msgid: dict[str, list[str]] = {msgid: [] for msgid in entries_by_normalized_msgid}

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
        entry_suggestions: list[Tuple[MergePOEntry, list[str]]] = []
        for msgid, suggestions in suggested_msgstrs_by_msgid.items():
            unique_suggestions: list[str] = []
            added_suggestions = {entry.entry.msgstr for entry in entries_by_normalized_msgid[msgid]}
            for msgstr in suggestions:
                if msgstr not in added_suggestions:
                    unique_suggestions.append(msgstr)
                    added_suggestions.add(msgstr)
            if unique_suggestions:
                for entry in entries_by_normalized_msgid[msgid]:
                    entry_suggestions.append((entry, unique_suggestions))

        for i, (entry, suggestions) in enumerate(entry_suggestions):
            options = [f"{repr(entry.entry.msgstr)} (Original)"] + [repr(msgstr) for msgstr in suggestions]
            title = f"TRANSLATION SUGGESTION ({i + 1} of {len(entry_suggestions)})\n\nThe entry with following msgid:\n\n{repr(entry.entry.msgid)}\n\nmay be translated as one of the following:\n\n"
            _, j = cast(PICK_RETURN_T[str], pick( options=options, title=title, indicator=PICK_INDICATOR))
            if j != 0:
                entry.entry.msgstr = suggestions[j - 1]

    def translate_interactively(self):
        matched_entries = [entry for entry in self.output_entries if self._is_matched_entry(entry)]
        for i, entry in enumerate(matched_entries):
            print(
                f"INTERACTIVE TRANSLATION ({i + 1} of {len(matched_entries)})\n\nEnter translation for the entry with the below msgid and msgstr or leave the input empty to leave its msgstr as it is\n\n{repr(entry.entry.msgid)} -> {repr(entry.entry.msgstr)}\n\n"
            )
            new_msgstr = input(": ")
            if new_msgstr:
                entry.entry.msgstr = new_msgstr
            print("\n")

    def sort_occurrences(self):
        for entry in self.output_entries:
            if self._is_matched_entry(entry):
                entry.entry.occurrences.sort()

    def confirm_new_entries(self):
        output_entries: list[MergePOEntry] = []
        added_entries_count = 0

        for entry in self.output_entries:
            if not entry.is_base_entry():
                added_entries_count += 1

        if not added_entries_count:
            return

        i = 1
        for entry in self.output_entries:
            if not entry.is_base_entry():
                # this msgid was excluded through a previous iteration, so skip it and do not add it
                if self._is_excluded_entry(entry):
                    continue

                options = ["Yes", "No", "Exclude (No and exclude this entry from this base file forever)"]
                title = f"ADDED ENTRY CONFIRMATION ({i} of {added_entries_count})\n\nDo you want to add the following entry to the output file?\n\n{entry.entry}"
                selected = cast(PICK_RETURN_T[str], pick(options=options, title=title, indicator=PICK_INDICATOR))
                _, j = selected
                if j == 0:
                    output_entries.append(entry)
                elif j == 1:
                    # the choice is 'No' so do nothing
                    pass
                elif j == 2:
                    self.excluded_msgids.add(entry.entry.msgid)
                i += 1
            else:
                output_entries.append(entry)

        self.output_entries = output_entries

    def describe_changes(self):
        if self.sort_entries:
            print(f"Sorted entries")
        if self.sort_references:
            print(f"Sorted references")

        added_entries_count = modified_entries_count = removed_entries_count = 0

        # Log output entries table
        data: list[list[Union[str, int]]] = []
        for entry in self.output_entries:
            changes = entry.describe_changes()
            if changes:
                if not entry.is_base_entry():
                    added_entries_count += 1
                else:
                    modified_entries_count += 1
            if self.verbose or changes:
                data.append([repr(entry.entry.msgid), repr(entry.entry.msgstr), entry.describe_changes()])

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
                data.append([repr(entry.entry.msgid), repr(entry.entry.msgstr), entry.removal_reason])

        headers = ["Msgid", "Msgstr", "Removal Reason"]
        maxcolwidths = [32, 32, 32]

        if data:
            print("[Removed entries]")
            print(tabulate(data, headers=headers, maxcolwidths=maxcolwidths, tablefmt="simple_grid", showindex=True))
            print()

        # Log repeated msgstrs
        data = [
            [repr(msgstr), len(entries)]
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
        # re-create pofile object of base file to get metadata
        output_file = pofile(self.base_path)
        output_file.clear()
        output_file.extend([entry.entry for entry in self.output_entries])
        output_file.save(self.output_path)


def main():
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
    parser.add_argument("--exclude", action="store_true", help="Enters interactive selection mode for entries, where chosen entries will be removed and become excluded from ever being added according to this base file")
    parser.add_argument("--unexclude", action="store_true", help="Interactively unexclude entries that were previously excluded")
    parser.add_argument("--reset-excluded", action="store_true", help="Reset the exclusion status of all entries")
    parser.add_argument("-c", "--confirm", action="store_true", help="Confirm every new entry added before adding it to the output file")
    parser.add_argument(
        "--reset-suggested-merges", action="store_true", help="Reset the merge suggestion status of all entries (re-suggest merge suggestions already seen)"
    )

    MergePO(**vars(parser.parse_args()))


if __name__ == "__main__":
    main()
