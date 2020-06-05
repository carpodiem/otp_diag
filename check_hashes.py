import otphashcheck
import json
from pprint import pprint


OTP_HOME = "/opt/otp"
TEST_HOME = "/tmp/opt/otp"
TEST_HOME2 = "/opt/otp"

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


dict1 = otphashcheck.dict_dir(TEST_HOME)
dict2 = otphashcheck.dict_dir(TEST_HOME2)

checked_manifest = otphashcheck.compare_hashes(dict1, correct_dict(dict2))

#pprint(dict1)
#print("++++++++++++++++++++++++ \n")
#pprint(dict2)
#print("++++++++++++++++++++++++ \n")
#pprint(correct_dict(dict2))

save_manifest(dict1,"/tmp/otp_manifest.json")
save_manifest(checked_manifest,"/tmp/manifest_checking.json")