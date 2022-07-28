'''
@Author: GamerNoTitle
@Date: 2022-07-28
@Website: https://bili33.top
@Github: https://github.com/GamerNoTitle
@Version: 1.1
'''

import os
import json
msg = r'''
  _  __          _                         _   ______      _                  _             
 | |/ /         | |                       | | |  ____|    | |                | |            
 | ' / ___ _   _| |__   ___   __ _ _ __ __| | | |__  __  _| |_ _ __ __ _  ___| |_ ___  _ __ 
 |  < / _ \ | | | '_ \ / _ \ / _` | '__/ _` | |  __| \ \/ / __| '__/ _` |/ __| __/ _ \| '__|
 | . \  __/ |_| | |_) | (_) | (_| | | | (_| | | |____ >  <| |_| | | (_| | (__| || (_) | |   
 |_|\_\___|\__, |_.__/ \___/ \__,_|_|  \__,_| |______/_/\_\\__|_|  \__,_|\___|\__\___/|_|   
            __/ |                                                                           
           |___/   Extract the keyboard input from wireshark datapack -- GamerNoTitle

Bug report: https://github.com/GamerNoTitle/KBE/issues/new
'''
print(msg)
file = input('Please input the file that you want to extract: ')
if file == '':
    print('You must specify a file to extract!')
    os._exit(0)
export = input(
    'Please input the path that you want to export to (Default: ./export.json): ')
if export == '':
    export = './export.json'
index = input('Please input the index of the packet you want to extract [usb.capdata(default)/usbhid.data]: ')
if index == '' or (index != 'usb.capdata' and index != 'usbhid.data'): index = 'usb.capdata'
syscall = os.popen(f'tshark -T json -r {file} > {export}')
if 'CommandNotFoundException' in syscall.read():
    print('You need to add tshark to your PATH first!')
    os._exit(0)

with open(export, 'rt', encoding='utf8') as export_file:
    json_data = json.loads(export_file.read())
    for data in json_data:
        # pprint(data)
        with open('usbdata.txt', 'a', encoding='utf8') as usb_file:
            try:
                usbdata = data['_source']['layers'][index]
                usb_file.write(usbdata + '\n')
            except:
                pass

normalKeys = {"04": "a", "05": "b", "06": "c", "07": "d", "08": "e", "09": "f", "0a": "g", "0b": "h", "0c": "i", "0d": "j", "0e": "k", "0f": "l", "10": "m", "11": "n", "12": "o", "13": "p", "14": "q", "15": "r", "16": "s", "17": "t", "18": "u", "19": "v", "1a": "w", "1b": "x", "1c": "y", "1d": "z", "1e": "1", "1f": "2", "20": "3", "21": "4", "22": "5", "23": "6", "24": "7", "25": "8", "26": "9", "27": "0",
              "28": "<RET>", "29": "<ESC>", "2a": "<DEL>", "2b": "\t", "2c": "<SPACE>", "2d": "-", "2e": "=", "2f": "[", "30": "]", "31": "\\", "32": "<NON>", "33": ";", "34": "'", "35": "<GA>", "36": ",", "37": ".", "38": "/", "39": "<CAP>", "3a": "<F1>", "3b": "<F2>", "3c": "<F3>", "3d": "<F4>", "3e": "<F5>", "3f": "<F6>", "40": "<F7>", "41": "<F8>", "42": "<F9>", "43": "<F10>", "44": "<F11>", "45": "<F12>"}
shiftKeys = {"04": "A", "05": "B", "06": "C", "07": "D", "08": "E", "09": "F", "0a": "G", "0b": "H", "0c": "I", "0d": "J", "0e": "K", "0f": "L", "10": "M", "11": "N", "12": "O", "13": "P", "14": "Q", "15": "R", "16": "S", "17": "T", "18": "U", "19": "V", "1a": "W", "1b": "X", "1c": "Y", "1d": "Z", "1e": "!", "1f": "@", "20": "#", "21": "$", "22": "%", "23": "^", "24": "&", "25": "*",
             "26": "(", "27": ")", "28": "<RET>", "29": "<ESC>", "2a": "<DEL>", "2b": "\t", "2c": "<SPACE>", "2d": "_", "2e": "+", "2f": "{", "30": "}", "31": "|", "32": "<NON>", "33": "\"", "34": ":", "35": "<GA>", "36": "<", "37": ">", "38": "?", "39": "<CAP>", "3a": "<F1>", "3b": "<F2>", "3c": "<F3>", "3d": "<F4>", "3e": "<F5>", "3f": "<F6>", "40": "<F7>", "41": "<F8>", "42": "<F9>", "43": "<F10>", "44": "<F11>", "45": "<F12>"}
output = []
keys = open('usbdata.txt')
for line in keys.read():
    try:
        if line[0] != '0' or (line[1] != '0' and line[1] != '2') or line[3] != '0' or line[4] != '0' or line[9] != '0' or line[10] != '0' or line[12] != '0' or line[13] != '0' or line[15] != '0' or line[16] != '0' or line[18] != '0' or line[19] != '0' or line[21] != '0' or line[22] != '0' or line[6:8] == "00":
            continue
        if line[6:8] in normalKeys.keys():
            output += [[normalKeys[line[6:8]]],
                       [shiftKeys[line[6:8]]]][line[1] == '2']
        else:
            output += ['[unknown]']
    except:
        pass
keys.close()

flag = 0
print('Original: ' + "".join(output))
for i in range(len(output)):
    try:
        a = output.index('<DEL>')
        del output[a]
        del output[a-1]
    except:
        pass
for i in range(len(output)):
    try:
        if output[i] == "<CAP>":
            flag += 1
            output.pop(i)
            if flag == 2:
                flag = 0
        if flag != 0:
            output[i] = output[i].upper()
    except:
        pass
os.remove('usbdata.txt')
os.remove(export)
print('output :' + "".join(output))
