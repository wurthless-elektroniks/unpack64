'''
Signature-related stuff I keep repeating in the various game drivers
'''

from signature import Signature

def pick_pattern(buffer: bytes,
                 patterns: list[Signature],
                 comparing_at_offset: int | None = None) -> tuple[Signature,int]:
    '''
    Given a list of Signatures, tries to find the first one it can in the buffer and,
    if found, returns its position with it.

    Returns None, None if nothing matched.
    '''
    for pattern in patterns:
        if comparing_at_offset is None:
            offset = pattern.find(buffer)
            return pattern, offset
        if pattern.compare(buffer, comparing_at_offset):
            return pattern, comparing_at_offset
        
    return None, None

def find_all_instances(buffer: bytes,
                       pattern: Signature,
                       align32: bool = True):
    
    instances = []
    offset = 0

    while True:
        offset = pattern.find(buffer, offset, align32=align32)
        if offset is None:
            return instances
        
        instances.append(offset)
        offset += pattern.size()
        if align32 and (offset & 3) != 0:
            offset = (offset + 4) & ~3

