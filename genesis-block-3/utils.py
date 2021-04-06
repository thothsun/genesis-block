# 相当于python2中的 origin.encode('hex')
def str2Hexstr(origin):
    return ''.join(
        ['{:x}'.format(ord(i)) if len('{:x}'.format(ord(i))) == 2 else '0' + '{:x}'.format(ord(i)) for i in origin])


# 相当于python2中的 origin.decode('hex')
def hexstr2Str(origin):
    return ''.join([chr(int(origin[i:i + 2], 16)) for i in range(0, len(origin), 2)])


def printInfo(obj):
    print(len(obj), ',', type(obj), ':', obj)
