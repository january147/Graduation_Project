#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Sun Mar  3 00:06:18 2019
# Author: January

import frida
import sys
import time
import os

def read_hook_code():
    filename = os.path.basename(__file__)
    hook_code_filename = filename[:-3] + '.js'
    hook_code_file = open(hook_code_filename)
    hook_code = hook_code_file.read()
    return hook_code

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(message['stack'])
    else:
        print(message)

hook_code = read_hook_code()
session = frida.get_usb_device().attach(int(sys.argv[1]))
script = session.create_script(hook_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
