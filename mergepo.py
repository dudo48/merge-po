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
def occurrences_match_regex(entry, regex):
    return [occ for occ in entry.occurrences if re.search(regex, occurrence_to_reference(occ))]


def merge_po(original_path, exported_path, output_path, regex, all_refs=False):
    exported_entry_by_msgid = {}
    for entry in polib.pofile(exported_path):
        matched_occurrences = occurrences_match_regex(entry, regex)
        if matched_occurrences:
            if not all_refs:
                entry.occurrences = matched_occurrences
            exported_entry_by_msgid[entry.msgid] = entry
    original_entries_to_remove = {
        en for en in polib.pofile(original_path) if occurrences_match_regex(en, regex) and en.msgid not in exported_entry_by_msgid
    }

    # merge existing entries
    stats = {'lines_added': 0, 'lines_removed': 0, 'merged_entries': 0}
    merged_entries = set()
    duplicate_merged_entries = set()
    original_entry_by_line_num = {en.linenum: en for en in polib.pofile(original_path)}
    with open(output_path, 'w', encoding='utf-8') as out_f, open(original_path, 'r', encoding='utf-8') as orig_f:
        previous_line = ''
        line_num = ref_index = 0
        original_entry = exported_entry = exported_entry_occurrences = None
        for line in orig_f:
            line_num += 1
            # assign entries
            if line_num in original_entry_by_line_num:
                original_entry = original_entry_by_line_num[line_num]
                if original_entry.msgid in exported_entry_by_msgid:
                    exported_entry = exported_entry_by_msgid[original_entry.msgid]
                    exported_entry_occurrences = set(exported_entry.occurrences)
                else:
                    exported_entry = exported_entry_occurrences = None
            # if we're inside a matched entry
            if original_entry and exported_entry:
                if is_reference(line):
                    # do not write unused refs
                    if (all_refs or re.search(regex, line)) and original_entry.occurrences[ref_index] not in exported_entry_occurrences:
                        stats['lines_removed'] += 1
                    else:
                        out_f.write(line)
                    ref_index += 1
                # add new lines at the end
                elif is_reference(previous_line):
                    new_occurrences = set(exported_entry.occurrences) - set(original_entry.occurrences)
                    for occ in new_occurrences:
                        out_f.write(f'{occurrence_to_reference(occ)}\n')
                    out_f.write(line)
                    if new_occurrences:
                        print(colored(f'Merged entry:  \'{exported_entry.msgid}\'', 'cyan'))
                        stats['merged_entries'] += 1
                    if exported_entry in merged_entries:
                        duplicate_merged_entries.add(exported_entry)
                    merged_entries.add(exported_entry)
                    stats['lines_added'] += len(new_occurrences)
                    ref_index = 0
                else:
                    out_f.write(line)
            elif original_entry and original_entry in original_entries_to_remove:
                stats['lines_removed'] += 1
            else:
                out_f.write(line)
            previous_line = line
    
    # log removed original entries
    for entry in original_entries_to_remove:
        print(colored(f'Removed entry: \'{entry.msgid}\'', 'red'))

    # add new entries at the bottom
    new_entries = set([en for en in exported_entry_by_msgid.values() if en not in merged_entries])
    if new_entries:
        with open(output_path, 'a', encoding='utf-8') as out_f:
            out_f.write('\n')
            for entry in new_entries:
                out_f.write(f'\n{str(entry)}')
                print(colored(f'Added entry:   \'{entry.msgid}\'', 'green'))
                stats['lines_added'] += str(entry).count('\n')

    
    print(
        'Added ' + colored(f'{len(new_entries)} entries', 'green')
        + ', merged ' + colored(f'{stats["merged_entries"]} entries', 'cyan')
        + ' and removed ' + colored(f'{len(original_entries_to_remove)} entries', 'red')
    )
    print('Added ' + colored(f'{stats["lines_added"]} line(s)', 'green') + ' and removed ' + colored(f'{stats["lines_removed"]} line(s)', 'red'))

    # warn about duplicates
    for entry in duplicate_merged_entries:
        print(colored(f'WARNING: duplicate merged entry: \'{entry.msgid}\'', 'yellow'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--original-path', required=True, help='Original file path')
    parser.add_argument('-e', '--exported-path', required=True, help='Exported file path')
    parser.add_argument('-o', '--output-path', required=True, help='Output file path')
    parser.add_argument('-r', '--regex', required=True, help='Match only entries that have occurrences matching this regex')
    parser.add_argument('--all-refs', action='store_true', help='Whether to add all different references present in '
                                                                'the exported file or add only those that match the'
                                                                ' specified regex')
    merge_po(**vars(parser.parse_args()))
