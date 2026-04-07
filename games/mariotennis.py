'''
Mario Tennis (custom packed, to be done MUCH later...)
'''




def _do_bootexe_unpack():

    # read byte
    # if byte is 0:
    #   copy next 8 bytes to output buffer
    #   increment input pointer by 9
    #   continue
    #
    # byte <<= 18
    # byte |= 0x00800000
    # let's call this ctrl_word
    #
    # if ctrl_word < 0: goto 80300184
    # delayslot:        ctrl_word <<= 1
    #   
    # read byte at input_ptr+0
    # if ctrl_word < 0: goto 80300200
    # delayslot:
    #   store byte at output_ptr+0
    #
    #
    # 80300180:
    #  ctrl_word <<= 1
    # 80300184:
    # if ctrl_word is 0:
    #   continue loop from start
    #   delayslot is a nop
    #
    # 
    #
    # 80300200:
    # - 
    #
    # 80300260:
    # if not end of file (not sure how it figures this out)
    # then it seems to hit an error case
    # otherwise, we're done - clear caches and return control to boot stub, which calls entrypoint
    #
