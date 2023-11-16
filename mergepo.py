import argparse
import re
import polib


# checks if the given line is a reference gettext line
def is_reference(line):
    return line.startswith('#:')


# return occurrence tuple converted to reference string
def occurrence_to_reference(occ):
    return '#: ' + (f'{occ[0]}:{occ[1]}' if occ[1] else occ[0])


# returns occurrences that contain a certain model name
def filter_match_regex(occurrences, regex):
    return [occ for occ in occurrences if re.search(regex, occurrence_to_reference(occ))]


def merge_po(original_path, exported_path, output_path, regex, all_refs=False):
    exported_model_entries_by_msgid = {}
    for entry in polib.pofile(exported_path):
        if filter_match_regex(entry.occurrences, regex):
            if not all_refs:
                entry.occurrences = filter_match_regex(entry.occurrences, regex)
            exported_model_entries_by_msgid[entry.msgid] = entry

    # merge existing entries
    total_lines_added = 0
    merged_entries_count = 0
    merged_entries = set()
    duplicate_merged_entries = set()
    original_entry_by_line_num = {en.linenum: en for en in polib.pofile(original_path)}
    with open(output_path, 'w', encoding='utf-8') as out_f, open(original_path, 'r', encoding='utf-8') as orig_f:
        line_num = 1
        original_entry = None
        previous_line = ''
        for line in orig_f:
            original_entry = original_entry_by_line_num.get(line_num, original_entry)
            if original_entry and original_entry.msgid in exported_model_entries_by_msgid and is_reference(previous_line) and not is_reference(line):
                exported_entry = exported_model_entries_by_msgid[original_entry.msgid]
                new_occurrences = set(exported_entry.occurrences) - set(original_entry.occurrences)
                for occ in new_occurrences:
                    out_f.write(f'{occurrence_to_reference(occ)}\n')
                if new_occurrences:
                    print(f'Merged entry: \'{exported_entry.msgid}\': added {len(new_occurrences)} line(s)')
                    merged_entries_count += 1
                if exported_entry in merged_entries:
                    duplicate_merged_entries.add(exported_entry)
                merged_entries.add(exported_entry)
                total_lines_added += len(new_occurrences)
            out_f.write(line)
            line_num += 1
            previous_line = line

    # add new entries at the bottom
    new_entries = set([en for en in exported_model_entries_by_msgid.values() if en not in merged_entries])
    if new_entries:
        with open(output_path, 'a', encoding='utf-8') as out_f:
            out_f.write('\n')
            for entry in new_entries:
                out_f.write(f'\n{str(entry)}')
                lines_added = str(entry).count('\n')
                print(f'Added entry: \'{entry.msgid}\': added {lines_added} line(s)')
                total_lines_added += lines_added

    print(f'Added {len(new_entries)} entries and merged {merged_entries_count} entries: added {total_lines_added} line(s)')

    # warn about duplicates
    for entry in duplicate_merged_entries:
        print(f'WARNING duplicate merged entry: \'{entry.msgid}\'')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--original-path', required=True, help='Original file path')
    parser.add_argument('-e', '--exported-path', required=True, help='Exported file path')
    parser.add_argument('-o', '--output-path', required=True, help='Output file path')
    parser.add_argument('-r', '--regex', required=True, help='Match only entries that have occurrences matching this regex')
    parser.add_argument('--all-refs', action='store_true', help='Whether to add all different references present in '
                                                                'the exported file or add only those that contain the'
                                                                ' specified model')
    merge_po(**vars(parser.parse_args()))
