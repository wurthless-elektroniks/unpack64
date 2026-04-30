'''
Signature-related stuff I keep repeating in the various game drivers
'''

from signature import Signature

def pick_pattern(buffer: bytes,
                 patterns: list[Signature]) -> tuple[Signature,int]:
    '''
    Given a list of Signatures, tries to find the first one it can in the buffer and,
    if found, returns its position with it.

    Returns None, None if nothing matched.
    '''
    for pattern in patterns:
        offset = pattern.find(buffer)
        if offset is not None:
            return pattern, offset
    return None, None