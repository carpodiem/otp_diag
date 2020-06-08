import otphashcheck
import json
from pprint import pprint
import configparser


OTP_HOME = "/opt/otp"
TEST_HOME = "/tmp/opt/otp"
TEST_HOME2 = "/opt/otp"

exclude = ["/tmp/opt/otp/nifi/logs","/tmp/opt/otp/indexes"]
#conf = configparser.ConfigParser()
#conf_dict = conf.read("otdiag.conf")

def save_manifest(manifest, filepath):
    with open(filepath, 'w', encoding='utf_8') as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    return


def correct_dict(dictc):
    dictc2 = dict()
    for key in dictc.keys():
        new_key = "/tmp" + key
        dictc2[new_key] = dictc[key]
    return dictc2

def create_excl_list(stanza):
    conf = configparser.ConfigParser()
    conf.read("otdiag.conf")
    excl_obj = []
    excl_obj.append(conf[stanza]["cache"])
    excl_obj.append(conf[stanza]["indexes"])

    return excl_obj

exclude = create_excl_list("otp")
print(exclude)
dict1 = otphashcheck.dict_dir(TEST_HOME,exclude)
dict2 = otphashcheck.dict_dir(TEST_HOME2,exclude)


print("++++++++++++++++++++++++ \n")
pprint(dict1)
print("++++++++++++++++++++++++ \n")
pprint(dict2)
print("++++++++++++++++++++++++ \n")
pprint(correct_dict(dict2))
print("++++++++++++++++++++++++ \n")

checked_manifest = otphashcheck.compare_hashes(dict1, correct_dict(dict2))
pprint(checked_manifest)
#save_manifest(dict1,"/tmp/otp_manifest.json")
#save_manifest(checked_manifest,"/tmp/manifest_checking.json")