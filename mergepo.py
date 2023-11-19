import argparse
import re

import polib
from termcolor import colored


# checks if the given line is a reference gettext line
def is_reference(line):
    return line.startswith('#:')


# return occurrence tuple converted to reference string
def occurrence_to_reference(occ):
    return '#: ' + (f'{occ[0]}:{occ[1]}' if occ[1] else occ[0])


# returns occurrences of the entry that match the regex
def occurrences_matching(occurrences, regex):
    return [occ for occ in occurrences if re.search(regex, occurrence_to_reference(occ))]


def merge_po(original_path, exported_path, output_path, regex, all_refs=False):
    exported_entry_by_msgid = {en.msgid: en for en in polib.pofile(exported_path)}
    matched_original_entries = set()
    for original_entry in polib.pofile(original_path):
        original_occurrences = occurrences_matching(original_entry.occurrences, regex)
        exported_entry, exported_occurrences = exported_entry_by_msgid.get(original_entry.msgid, None), []
        if exported_entry:
            exported_occurrences = occurrences_matching(exported_entry.occurrences, regex)
        # an original entry is matched if occurrences of its msgid entry are matched in original or exported file
        if original_occurrences or exported_occurrences:
            matched_original_entries.add(original_entry)

    # compute new references and occurrences to remove
    new_references, occurrences_to_remove, entries_to_remove = {}, {}, set()
    for original_entry in matched_original_entries:
        if original_entry.msgid in exported_entry_by_msgid:
            exported_entry = exported_entry_by_msgid[original_entry.msgid]

            # compute new references
            not_in_original = set(exported_entry.occurrences) - set(original_entry.occurrences)
            if not all_refs:
                not_in_original = occurrences_matching(not_in_original, regex)
            new_references[original_entry] = sorted([occurrence_to_reference(occ) for occ in not_in_original])

            # compute occurrences to remove
            not_in_exported = set(original_entry.occurrences) - set(exported_entry.occurrences)
            if not all_refs:
                not_in_exported = occurrences_matching(not_in_exported, regex)
            occurrences_to_remove[original_entry] = set(not_in_exported)
        else:
            # remove entries with msgids not in exported
            entries_to_remove.add(original_entry)

    # statistical variables
    lines_added = lines_removed = merged_entries_count = 0

    # merge existing entries
    original_entry_by_line_num = {en.linenum: en for en in polib.pofile(original_path)}
    with open(output_path, 'w', encoding='utf-8') as out_f, open(original_path, 'r', encoding='utf-8') as orig_f:
        previous_line = ''
        line_num = ref_index = 0
        original_entry = None
        for line in orig_f:
            line_num += 1
            write_line = True
            original_entry = original_entry_by_line_num.get(line_num, original_entry)

            # remove entry
            if original_entry in entries_to_remove:
                write_line = False
                if line_num in original_entry_by_line_num:
                    print(colored(f'Removed entry: \'{original_entry.msgid}\'', 'red'))
            
            # remove reference
            elif occurrences_to_remove.get(original_entry, None) and is_reference(line):
                write_line = original_entry.occurrences[ref_index] not in occurrences_to_remove[original_entry]
            
            # add references
            elif new_references.get(original_entry, None) and not is_reference(line) and is_reference(previous_line):
                for ref in new_references[original_entry]:
                    out_f.write(ref + '\n')
                    lines_added += 1
                print(colored(f'Merged entry:  \'{original_entry.msgid}\'', 'cyan'))
                merged_entries_count += 1

            if write_line:
                out_f.write(line)
            else:
                lines_removed += 1
            previous_line = line
            ref_index = ref_index + 1 if is_reference(line) else 0
    
    # add new entries at the bottom
    matched_original_entries_msgids = {en.msgid for en in matched_original_entries}
    new_entries = [en for en in exported_entry_by_msgid.values() if occurrences_matching(en.occurrences, regex) and en.msgid not in matched_original_entries_msgids]
    if new_entries:
        with open(output_path, 'a', encoding='utf-8') as out_f:
            out_f.write('\n')
            for entry in new_entries:
                out_f.write(f'\n{str(entry)}')
                print(colored(f'Added entry:   \'{entry.msgid}\'', 'green'))
                lines_added += str(entry).count('\n')

    print(
        'Added ' + colored(f'{len(new_entries)} entries', 'green')
        + ', merged ' + colored(f'{merged_entries_count} entries', 'cyan')
        + ' and removed ' + colored(f'{len(entries_to_remove)} entries', 'red')
    )
    print(
        'Added ' + colored(f'{lines_added} line(s)', 'green')
        + ' and removed ' + colored(f'{lines_removed} line(s)', 'red')
    )

    # warning about duplicates
    matched_original_entries_msgids = set()
    for entry in matched_original_entries:
        if entry.msgid in matched_original_entries_msgids:
            print(colored(f'Duplicate entry: \'{entry.msgid}\'', 'yellow'))
        matched_original_entries_msgids.add(entry.msgid)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--original-path', required=True, help='Original file path')
    parser.add_argument('-e', '--exported-path', required=True, help='Exported file path')
    parser.add_argument('-o', '--output-path', required=True, help='Output file path')
    parser.add_argument('-r', '--regex', required=True, help='Match only entries that have occurrences matching this regex')
    parser.add_argument('-a', '--all-refs', action='store_true', help='Whether to add all different references present in '
                                                                'the exported file or add only those that match the'
                                                                ' specified regex')
    merge_po(**vars(parser.parse_args()))
