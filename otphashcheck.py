import os
import hashlib
import io

"""
Модуль для проверки контрольных сумм (хэш md5).
1. Создает контрольный список файлов эталонной системы.
2. Создает контрольные суммы из эталонной системы.
3. Сравнивает эталоные контрольные суммы с проверяемыми. Результат записывает в новый список.
"""


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


def dict_dir(direct):
    """
    Creating manifest-list of files and directories
    Every string consists of
    [type-of-object, permissions, os-path, hash-of-file]
    """
    file_list_path = dict()
    for r, d, f in os.walk(direct):
        dirperm = obj_stats(r)
        file_list_path[r] = ["d", dirperm, "-"]
        for file in f:
            filepath = os.path.join(r, file)
            fileperm = obj_stats(filepath)
            filehash = hash_object(filepath)
            file_list_path[filepath] = ["f", fileperm, filehash]
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
    string = str
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


def obj_stats(objpath):
    """
    Get permissions of a file
    """
    permiss = os.stat(objpath).st_mode
    return oct(permiss & 0o777)


def compare_hashes(l_ethalon, l_current):
    """
    Compares ethalon manifest file with the current hash checking dictionary
    :param l_ethalon:
    :param l_current:
    :return:
    """
    comp_dict = dict()
    for key in l_ethalon.keys():
        if l_current[key]:
            hash_eth = l_ethalon[key][2]
            hash_cur = l_current[key][2]
            if hash_eth != hash_cur:
                comp_dict[key] = {"ethalon": hash_eth, "wrong": hash_cur}
        else:
            comp_dictp[key] = "missed file"
    return comp_dict

