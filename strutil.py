
def extract_cstring(data: bytes):
    return data.partition(b'\x00')[0].decode('ascii')
