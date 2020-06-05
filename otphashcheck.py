import os
import hashlib
import io

"""
Модуль для проверки контрольных сумм (хэш md5).
1. Создает контроьный список файлов эталонной системы.
2. Создает контрольные суммы из эталонной системы.
3. Сравнивает эталоные контрольные суммы с проверяемыми.
"""

OTP_HOME = "/opt/otp"
TEST_HOME = "/opt"
string = str


def list_dir(direct):
    """
    Creating manifest-list of files and directories
    Every string consists of
    [type-of-object, permissions, os-path, hash-of-file]
    """
    file_list_path = []
    for r, d, f in os.walk(direct):
        dirperm = obj_stats(r)
        dirsting = ["d", dirperm, r, "-"]
        file_list_path.append(dirsting)
        for file in f:
            filepath = os.path.join(r, file)
            fileperm = obj_stats(filepath)
            filehash = hash_object(filepath)
            filestring = ["f", fileperm, filepath, filehash]
            file_list_path.append(filestring)
#    for file_path in file_list_path:
#        print(file_path)
    return file_list_path


def hash_of_file(filename):
    """
    Get md5 checksum of a file
    """
    hash_md5 = hashlib.md5()
    with open(filename,'rb') as check_its_hash:
        for block in iter(lambda: check_its_hash.read(4096), b""):
            hash_md5.update(block)
    return hash_md5.hexdigest()


def hash_compare(original_list, installed_list):
    return


def hash_object(filename, size=-1):
    """
    Computes an object ID from a file the way Git does. [1]_

    :param filename: Path to file.
    :type filename: string
    :param size: Length of file.
    :return: Object ID.
    :rtype: string

    .. rubric:: Footnotes
    .. [1] `Git Tip of the Week: Objects <http://goo.gl/rvfWtM>`

    """
    if size == -1:
        size = os.path.getsize(filename)
    object_id = hashlib.sha1()
    object_id.update(b'blob ' + bytes(size) + b'\0')
    if size > 0:
        with io.open(filename, 'rb') as istream:
            block = bytearray(65535)
            while True:
                length = istream.readinto(block)
                if length == 0:
                    break
                object_id.update(block[:length])
    return string(object_id.hexdigest())


#def add_hashes(filelist):
#    """
#    Enrich manifest list with hashes
#    """
#    for f in filelist:
#        if f[0] != "d":
#            hash = hash_object(f[2])
#            f.append(hash)
#        else:
#            f.append("-")
#    return filelist


def obj_stats(objpath):
    """
    Get permissions of a file
    """
    permiss = os.stat(objpath).st_mode
    return oct(permiss & 0o777)


total_list = list_dir(TEST_HOME)

for i in total_list:
    print(i)

