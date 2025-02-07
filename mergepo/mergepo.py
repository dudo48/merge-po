"""
The happiness of most people is not ruined by great catastrophes or fatal errors,
but by the repetition of slowly destructive little things.
    - Ernest Dimnet
"""

import argparse
import hashlib
import pickle
from pathlib import Path
from typing import Optional, Union, cast

from pick import PICK_RETURN_T, pick
from polib import pofile
from tabulate import tabulate

from .constants import PERSISTENT_DATA_PATH, PICK_INDICATOR
from .entry import EntryRemovalReason, EntrySource, MergePOEntry
from .helpers import load_persistent_data, save_persistent_data


class MergePO:
    def __init__(
        self,
        base_path: Path,
        output_path: Optional[Path] = None,
        exported_path: Optional[Path] = None,
        sort_entries: bool = False,
        sort_references: bool = False,
        reset_suggested_merges: bool = False,
        reset_added_msgids: bool = False,
        reset_removed_msgids: bool = False,
    ):
        self.base_path = Path(base_path).resolve()
        self.base_pofile = pofile(str(self.base_path))
        self.base_file_identifier = hashlib.sha1(
            pickle.dumps(
                (self.base_pofile.header, str(self.base_pofile.metadata_as_entry()))
            )
        ).hexdigest()

        self.output_path = Path(output_path or base_path).resolve()
        self.exported_path = Path(exported_path).resolve() if exported_path else None

        self.persistent_data_path = PERSISTENT_DATA_PATH / self.base_file_identifier
        self.suggested_merges_file_path = self.persistent_data_path / "suggested_merges"
        self.added_msgids_file_path = self.persistent_data_path / "added_msgids"
        self.removed_msgids_file_path = self.persistent_data_path / "removed_msgids"

        self.sort_entries = sort_entries
        self.sort_references = sort_references

        self.reset_suggested_merges = reset_suggested_merges
        self.reset_added_msgids = reset_added_msgids
        self.reset_removed_msgids = reset_removed_msgids

        self.entries: list[MergePOEntry] = []
        self.output_entries: list[MergePOEntry] = []

        self.suggested_merges: "dict[str, set[str]]" = (
            load_persistent_data(self.suggested_merges_file_path) or dict()
        )
        self.added_msgids: "set[str]" = (
            load_persistent_data(self.added_msgids_file_path) or set()
        )
        self.removed_msgids: "set[str]" = (
            load_persistent_data(self.removed_msgids_file_path) or set()
        )

    def non_removed_output_entries(self):
        for entry in self.output_entries:
            if not entry.removal_reason:
                yield entry

    def start(self):
        self._run()

        save_persistent_data(self.suggested_merges_file_path, self.suggested_merges)
        save_persistent_data(self.added_msgids_file_path, self.added_msgids)
        save_persistent_data(self.removed_msgids_file_path, self.removed_msgids)

        self.save_output_file()
        self.describe_changes()

    def _run(self):
        self.find_entries()
        self.add_base_entries()
        self.filter_duplicates()
        if self.exported_path:
            self.add_exported_entries()
            self.filter_not_in_exported()

        if self.reset_suggested_merges:
            self.suggested_merges.clear()

        self.suggest_merge_same_msgid()
        self.filter_no_occurrences()
        self.filter_duplicate_occurrences()

        if self.reset_added_msgids:
            self.added_msgids.clear()

        if self.reset_removed_msgids:
            self.removed_msgids.clear()

        self.filter_and_set_added_and_removed()
        self.filter_removed_entries()

        if self.sort_entries:
            self.output_entries.sort()

        if self.sort_references:
            self.sort_occurrences()

    def _group_output_entries_by_msgid(self):
        result: dict[str, list[MergePOEntry]] = {}
        for entry in self.non_removed_output_entries():
            if entry.msgid in result:
                result[entry.msgid].append(entry)
            else:
                result[entry.msgid] = [entry]
        return result

    def _group_output_entries_by_msgstr(self):
        result: dict[str, list[MergePOEntry]] = {}
        for entry in self.non_removed_output_entries():
            if entry.msgstr in result:
                result[entry.msgstr].append(entry)
            else:
                result[entry.msgstr] = [entry]
        return result

    def _group_output_entries_by_msgid_msgstr(self):
        result: dict[tuple[str, str], list[MergePOEntry]] = {}
        for entry in self.non_removed_output_entries():
            key = (entry.msgid, entry.msgstr)
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
            self.entries.append(MergePOEntry(entry, EntrySource.BASE))

        if self.exported_path:
            for entry in pofile(str(self.exported_path)):
                self.entries.append(MergePOEntry(entry, EntrySource.EXPORTED))

    def add_base_entries(self):
        for entry in self.entries:
            if entry.is_base_entry():
                self.output_entries.append(entry)

    def add_exported_entries(self):
        entries_by_msgid = self._group_output_entries_by_msgid()
        for entry in self.entries:
            if not entry.is_exported_entry():
                continue
            matched_output_entries = entries_by_msgid.get(entry.msgid, [])
            if matched_output_entries:
                MergePOEntry.match_occurrences_multi(entry, matched_output_entries)
            else:
                self.output_entries.append(entry)

    def filter_duplicates(self):
        """
        Filter out entries which are duplicate in both msgid and msgstr
        """
        added_entries: dict[tuple[str, str], MergePOEntry] = {}
        for entry in self.non_removed_output_entries():
            key = (entry.msgid, entry.msgstr)
            if key in added_entries:
                added_entries[key].merge_occurrences(entry)
                entry.removal_reason = EntryRemovalReason.DUPLICATE
            else:
                added_entries[key] = entry

    def filter_duplicate_occurrences(self):
        """
        Filter out duplicate occurrences for the same entry
        """
        for entry in self.non_removed_output_entries():
            entry.filter_duplicate_occurrences()

    def filter_not_in_exported(self):
        """
        Filter out entries with msgids not present in exported file
        """
        exported_msgids = {
            entry.msgid for entry in self.entries if entry.is_exported_entry()
        }
        for entry in self.non_removed_output_entries():
            if entry.msgid not in exported_msgids:
                entry.removal_reason = EntryRemovalReason.NOT_IN_EXPORTED

    def filter_no_occurrences(self):
        """
        Filter out entries with empty occurrences list
        """
        for entry in self.non_removed_output_entries():
            if not entry.occurrences:
                entry.removal_reason = EntryRemovalReason.NO_OCCURRENCES

    def filter_removed_entries(self):
        """
        Actually filter out removed entries from output entries
        """
        self.output_entries = list(self.non_removed_output_entries())

    def filter_and_set_added_and_removed(self):
        """Prevent addition/removal of entries which were previously added/removed
        and add msgids of newly added/removed entries to their respective sets"""
        output_entries: list[MergePOEntry] = []
        for entry in self.output_entries:
            msgid = entry.msgid
            if not entry.is_base_entry() and msgid in self.added_msgids:
                continue
            if (
                entry.removal_reason is EntryRemovalReason.NOT_IN_EXPORTED
                and msgid in self.removed_msgids
            ):
                entry.removal_reason = None
            output_entries.append(entry)

        self.output_entries = output_entries
        for entry in self.output_entries:
            added = not entry.is_base_entry()
            removed = entry.removal_reason is EntryRemovalReason.NOT_IN_EXPORTED
            if added and not removed:
                self.added_msgids.add(entry.msgid)
            if removed and not added:
                self.removed_msgids.add(entry.msgid)

    def suggest_merge_same_msgid(self):
        """
        Suggest to merge occurrences of entries with same msgids
        """
        entries_by_msgid: dict[str, list[MergePOEntry]] = {}
        for msgid, entries in self._group_output_entries_by_msgid().items():
            msgstr_set = {entry.msgstr for entry in entries}
            if (
                len(entries) > 1
                and self.suggested_merges.get(msgid, set()) != msgstr_set
            ):
                entries_by_msgid[msgid] = entries

        for i, (msgid, entries) in enumerate(entries_by_msgid.items()):
            while len(entries) > 1:
                options = [repr(entry.msgstr) for entry in entries]
                title = (
                    f"ENTRY MERGE SUGGESTION ({i + 1} of {len(entries_by_msgid)})\n\n"
                    f"The entries with the following msgstrs have the same msgid:"
                    f"\n\n{repr(msgid)}\n\n"
                    f"Do you want to merge any of them? Select the ones you want to be merged and removed"
                    f" and then select the entry to merge into LAST\n"
                    f"or leave the selection empty to stop merging for this msgid\n"
                    f"(press SPACE to mark, ENTER to continue/skip)"
                )
                selected = cast(
                    "list[PICK_RETURN_T[str]]",
                    pick(
                        options=options,
                        title=title,
                        indicator=PICK_INDICATOR,
                        multiselect=True,
                    ),
                )
                selected_indices = [j for _, j in selected]
                if not selected_indices:
                    self.suggested_merges[msgid] = {entry.msgstr for entry in entries}
                    break

                removed_indices: set[int] = set()
                destination = entries[selected_indices[-1]]
                for j in selected_indices[:-1]:
                    entry = entries[j]
                    destination.merge_occurrences(entry)
                    removed_indices.add(j)
                    entry.removal_reason = EntryRemovalReason.MERGED
                entries = [
                    entry for j, entry in enumerate(entries) if j not in removed_indices
                ]

    def sort_occurrences(self):
        for entry in self.output_entries:
            entry.occurrences.sort()

    def describe_changes(self):
        if self.sort_entries:
            print("Sorted entries")
        if self.sort_references:
            print("Sorted references")

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
            if changes:
                data.append(
                    [
                        repr(entry.msgid),
                        repr(entry.msgstr),
                        entry.describe_changes(),
                    ]
                )

        headers = ["Msgid", "Msgstr", "Changes"]
        maxcolwidths = [32, 32, 32]

        if data:
            print("[Output file entries]")
            print(
                tabulate(
                    data,
                    headers=headers,
                    maxcolwidths=maxcolwidths,
                    tablefmt="simple_grid",
                    showindex=True,
                )
            )
            print()

        # Log removed entries table
        data = []
        for entry in self.entries:
            if entry.removal_reason and entry.is_base_entry():
                removed_entries_count += 1
                data.append(
                    [
                        repr(entry.msgid),
                        repr(entry.msgstr),
                        entry.removal_reason.value,
                    ]
                )

        headers = ["Msgid", "Msgstr", "Removal Reason"]
        maxcolwidths = [32, 32, 32]

        if data:
            print("[Removed entries]")
            print(
                tabulate(
                    data,
                    headers=headers,
                    maxcolwidths=maxcolwidths,
                    tablefmt="simple_grid",
                    showindex=True,
                )
            )
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
            print(
                tabulate(
                    data,
                    headers=headers,
                    maxcolwidths=maxcolwidths,
                    tablefmt="simple_grid",
                )
            )
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
        output_file = pofile(str(self.base_path))
        output_file.clear()
        output_file.extend([entry.entry for entry in self.output_entries])
        output_file.save(str(self.output_path))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--base-path", required=True, help="Base file path")
    parser.add_argument(
        "-o",
        "--output-path",
        help="Output file path, if not given defaults to base path (replaces original file)",
    )
    parser.add_argument("-e", "--exported-path", help="Exported file path")
    parser.add_argument(
        "-S",
        "--sort-entries",
        action="store_true",
        help="If this flag is passed then the entries are sorted in the output file according"
        " to msgid and msgstr",
    )
    parser.add_argument(
        "-s",
        "--sort-references",
        action="store_true",
        help="If this flag is passed then the references of each entry are sorted in the output file",
    )
    parser.add_argument(
        "--reset-suggested-merges",
        action="store_true",
        help="Reset the merge suggestion status of all entries (re-suggest merge suggestions already seen)",
    )
    parser.add_argument(
        "-r",
        "--reset-added-msgids",
        action="store_true",
        help="Reset the addition status of all entries (re-add entries with msgids added from a previous run if they do not exist in the base file)",
    )
    parser.add_argument(
        "-R",
        "--reset-removed-msgids",
        action="store_true",
        help="Reset the removal status of all entries (remove again entries with msgids removed from a previous run if they do exist in the base file)",
    )

    merge_po = MergePO(**vars(parser.parse_args()))
    merge_po.start()


if __name__ == "__main__":
    main()
