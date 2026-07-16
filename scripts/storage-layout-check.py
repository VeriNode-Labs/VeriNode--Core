#!/usr/bin/env python3
import sys
import re
import subprocess

def get_file_content_from_git(branch, filepath):
    try:
        # Get file content from specific git branch/commit
        result = subprocess.run(
            ['git', 'show', f'{branch}:{filepath}'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return result.stdout
    except Exception:
        return None

def parse_slots_and_structs(content):
    if not content:
        return {}, {}
    
    # Parse slot definitions: pub const NAME_SLOT: [u8; 32] = [ ... ];
    # Match multiline arrays as well
    slot_pattern = re.compile(
        r'pub\s+const\s+(\w+_SLOT)\s*:\s*\[u8;\s*32\]\s*=\s*\[([^\]]+)\]\s*;',
        re.MULTILINE
    )
    
    slots = {}
    for match in slot_pattern.finditer(content):
        name = match.group(1)
        bytes_str = match.group(2)
        # Parse bytes, e.g., 0x60, 0x01, or 1; 32
        bytes_str = bytes_str.strip()
        if ';' in bytes_str:
            val, count = bytes_str.split(';')
            val = int(val.strip(), 0)
            count = int(count.strip())
            byte_list = [val] * count
        else:
            byte_list = [int(x.strip(), 0) for x in bytes_str.split(',') if x.strip()]
        
        slots[name] = bytes(byte_list)

    # Parse structs: pub struct StructName { ... }
    struct_pattern = re.compile(
        r'pub\s+struct\s+(\w+)\s*\{([^\}]+)\}',
        re.MULTILINE
    )
    structs = {}
    for match in struct_pattern.finditer(content):
        name = match.group(1)
        fields_str = match.group(2)
        # Clean fields
        fields = []
        for line in fields_str.split('\n'):
            line = line.strip()
            if line and not line.startswith('//'):
                # Extract field name and type, e.g., pub max_validators: u32
                field_match = re.match(r'(?:pub\s+)?(\w+)\s*:\s*([\w<>:\[\];\s]+)', line)
                if field_match:
                    f_name = field_match.group(1)
                    f_type = field_match.group(2).replace(' ', '')
                    fields.append((f_name, f_type))
        structs[name] = fields

    return slots, structs

def main():
    filepath = 'src/proxy/storage-layout.rs'
    
    # Read current file
    try:
        with open(filepath, 'r') as f:
            current_content = f.read()
    except FileNotFoundError:
        print(f"Error: {filepath} not found.")
        sys.exit(1)
        
    current_slots, current_structs = parse_slots_and_structs(current_content)
    
    # Read base branch (origin/main)
    base_content = get_file_content_from_git('origin/main', filepath)
    if base_content is None:
        # Fallback to main
        base_content = get_file_content_from_git('main', filepath)
        
    if not base_content:
        print("No previous implementation layout found on main branch. Skipping diff checks, performing self-checks.")
        base_slots, base_structs = {}, {}
    else:
        base_slots, base_structs = parse_slots_and_structs(base_content)
        
    collision_detected = False
    
    # Self-check: Look for duplicate values in current slots
    slot_values = {}
    for name, value in current_slots.items():
        if value in slot_values:
            print(f"COLLISION WARNING: Slot '{name}' collides with '{slot_values[value]}' at value {value.hex()}")
            collision_detected = True
        else:
            slot_values[value] = name
            
    # Diff check: Compare slots with base/old implementation
    for name, value in base_slots.items():
        if name in current_slots:
            if current_slots[name] != value:
                print(f"COLLISION WARNING: Slot '{name}' has changed value from {value.hex()} to {current_slots[name].hex()}")
                collision_detected = True
        else:
            print(f"WARNING: Slot '{name}' was removed from the storage layout.")
            
    # Diff check: Compare structs to detect shifts in fields/ordering
    for name, fields in base_structs.items():
        if name in current_structs:
            curr_fields = current_structs[name]
            # Check if fields were reordered or modified in a way that shifts layouts
            min_len = min(len(fields), len(curr_fields))
            for i in range(min_len):
                if fields[i] != curr_fields[i]:
                    print(f"COLLISION WARNING: Struct '{name}' field layout shifted/changed at index {i}:")
                    print(f"  Old: {fields[i][0]}: {fields[i][1]}")
                    print(f"  New: {curr_fields[i][0]}: {curr_fields[i][1]}")
                    collision_detected = True
            if len(curr_fields) < len(fields):
                print(f"COLLISION WARNING: Struct '{name}' fields were removed. This will corrupt storage decoding.")
                collision_detected = True
        else:
            print(f"WARNING: Struct '{name}' was removed from the storage layout.")
            
    if collision_detected:
        print("Storage layout verification failed! Potential collision or layout corruption detected.")
        sys.exit(1)
    else:
        print("Storage layout verification passed successfully. No collisions detected.")
        sys.exit(0)

if __name__ == '__main__':
    main()
