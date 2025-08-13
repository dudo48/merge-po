from collections import Counter
from enum import Enum
from typing import Optional, Tuple, cast

from pick import PICK_RETURN_T, pick
from polib import POEntry

from .constants import PICK_INDICATOR

Occurrence = Tuple[str, str]


class EntrySource(Enum):
    BASE = 0
    EXPORTED = 1


class EntryRemovalReason(Enum):
    DUPLICATE = "Duplicate entry"
    NOT_IN_EXPORTED = "Not in exported file"
    NO_OCCURRENCES = "No references"
    MERGED = "Merged with another entry"


class MergePOEntry:
    def __init__(self, entry: POEntry, source: EntrySource):
        self.entry = entry
        self.source = source
        self.original_occurrences = [occurrence for occurrence in entry.occurrences]
        self.removal_reason: Optional[EntryRemovalReason] = None

    @property
    def msgid(self):
        return self.entry.msgid

    @msgid.setter
    def msgid(self, value: str):
        self.entry.msgid = value

    @property
    def msgstr(self):
        return self.entry.msgstr

    @msgstr.setter
    def msgstr(self, value: str):
        self.entry.msgstr = value

    @property
    def occurrences(self):
        return self.entry.occurrences

    @occurrences.setter
    def occurrences(self, value: "list[Occurrence]"):
        self.entry.occurrences = value

    def __key(self):
        return self.msgid, self.msgstr

    def __repr__(self):
        return f"MergePOEntry({repr(self.msgid)}, {repr(self.msgstr)})"

    def __lt__(self, other: "MergePOEntry"):
        return self.__key() < other.__key()

    def filter_duplicate_occurrences(self):
        # used dict keys to maintain list order
        self.occurrences = list(dict.fromkeys(self.occurrences))

    def merge_occurrences(self, other: "MergePOEntry"):
        """
        Union occurrences with another entry
        """
        self.occurrences.extend(
            o for o in other.occurrences if o not in set(self.occurrences)
        )

    def match_occurrences(self, other: "MergePOEntry"):
        """
        Set entry's occurrences to match occurrences of another entry
        """
        self.occurrences = [o for o in self.occurrences if o in set(other.occurrences)]
        self.occurrences.extend(
            o for o in other.occurrences if o not in set(self.occurrences)
        )

    def is_base_entry(self):
        return self.source is EntrySource.BASE

    def is_exported_entry(self):
        return self.source is EntrySource.EXPORTED

    def describe_changes(self):
        changes: list[str] = []

        # Tell if entry was not originally in the base file
        if self.is_exported_entry():
            changes.append("Added from exported file")

        # Calculate added and removed occurrences
        occurrences = Counter(self.occurrences)
        original_occurrences = Counter(self.original_occurrences)

        added_occurrences = occurrences - original_occurrences
        removed_occurrences = original_occurrences - occurrences

        if added_occurrences or removed_occurrences:
            changes.append(
                f"Added {sum(added_occurrences.values())} and removed {sum(removed_occurrences.values())} references"
            )

        return ", ".join(changes)

    @staticmethod
    def match_occurrences_multi(
        source: "MergePOEntry", destinations: "list[MergePOEntry]"
    ):
        """
        Set destination entries to match the source entry's occurrences, giving choice in case of ambiguity
        """
        if len(destinations) == 1:
            return destinations[0].match_occurrences(source)

        # ambiguous occurrences are occurrences which are present in source but not present in any destination entry
        # therefore, they're ambiguous because it is not clear which entry should be their destination
        source_occurrences: set[Occurrence] = set(source.occurrences)
        unambiguous_occurrences: set[Occurrence] = set()
        for entry in destinations:
            new_occurrences: list[Occurrence] = []
            for occurrence in entry.occurrences:
                if occurrence in source_occurrences:
                    new_occurrences.append(occurrence)
                    unambiguous_occurrences.add(occurrence)
            entry.occurrences = new_occurrences

        ambiguous_occurrences = [
            o for o in source.occurrences if o not in unambiguous_occurrences
        ]
        for i, occurrence in enumerate(sorted(ambiguous_occurrences)):
            options = [repr(entry.msgstr) for entry in destinations]
            title = f"REFERENCE AMBIGUITY ({i + 1} of {len(ambiguous_occurrences)})\n\nDuplicate msgid found: {repr(source.msgid)}\nChoose a msgstr for the below reference:\n\n{occurrence[0]}"
            _, j = cast(
                PICK_RETURN_T[str],
                pick(options=options, title=title, indicator=PICK_INDICATOR),
            )
            destinations[j].occurrences.append(occurrence)

    @staticmethod
    def get_normalized_msgid(msgid: str):
        return msgid.strip().lower()
