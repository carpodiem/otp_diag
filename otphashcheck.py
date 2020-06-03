import os
import json
import hashlib
from pprint import pprint

"""
Модуль для проверки контрольных сумм (хэш md5).
1. Создает контроьный список файлов эталонной системы.
2. Создает контрольные суммы из эталонной системы.
3. Сравнивает эталоные контрольные суммы с проверяемыми.
"""


def hash_of_file(filename):
"""
Get md5 checksum of a file
"""
    hash_md5 = hashlib.md5()
    with open(filename,'rb') as check_its_hash:
        for block in iter(lambda: check_its_hash.read(4096), b""):
            hash_md5.update(block)
    return hash_md5.hexdigest()

print(hash_of_file('file1.txt'))