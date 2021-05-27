#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# DFIR Deaddrop - quick http client/server file transfer for IR evidence collection. 
# This is http only so password protect or encrypt the evidence prior to transfer
# Author: Sean Frank 

import aiofiles
import aiohttp
import asyncio
import base64
import ctypes
import hashlib
import logging
import os
import string
import sys
import time
from aiohttp import web
from colorama import Fore, Back, Style
from Crypto.Cipher import AES
from datetime import datetime
from datetime import date

# Cipher/Encrypt/Hash Functions. Currently only using the hashing function to hash the DGA key for the ETag Header.
def _getcipher():
    key_var = "key"
    enc_key = dead_dga_algorithm(key_var)
    enc_key = bytes(enc_key, 'utf-8')
    cipher = AES.new(enc_key, AES.MODE_ECB)
    blksz = 16
    padding = '{'
    pad = lambda s: s + (blksz - len(s) % blksz) * padding
    return cipher, pad, padding

def encrypt(clear_text):
    get_cipher = _getcipher()
    cipher = get_cipher[0]
    pad = get_cipher[1]
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s).encode('utf-8'))).decode('ascii')
    encoded = EncodeAES(cipher, clear_text)
    return encoded

def decrypt(enc_passwd):
    get_cipher = _getcipher()
    cipher = get_cipher[0]
    padding = get_cipher[2]
    DecodeAES = lambda c, b: c.decrypt(base64.b64decode(bytes(b, 'utf-8'))).decode('ascii').rstrip(padding)
    decoded = DecodeAES(cipher, enc_passwd)
    return decoded

def hash_keys_hosts(keys_hosts):
    host_hash = hashlib.sha256(keys_hosts.encode('utf-8')).hexdigest()
    return host_hash

# DGA Function. Currently only being used to create a key for the ETag header verification
# Seeds can be change so as not to use the same key.
def _dead_month_seed():
    mnthseed = {
        '01': '12711234',
        '02': '14835678',
        '03': '16159012',
        '04': '18773456',
        '05': '10797890',
        '06': '12811234',
        '07': '14435678',
        '08': '16959012',
        '09': '18973456',
        '10': '10497890',
        '11': '12411234',
        '12': '14435678'
        }
    return mnthseed

def dead_dga_algorithm(key_domain):
    if key_domain == 'key':
        init_i = 32
        idx = 256
    elif key_domain == 'domain':
        init_i = 16
        idx = 128
    today_tuple = date.today()
    tday_list = str(today_tuple).split('-')
    cur_day = tday_list[2]
    cur_month = tday_list[1]
    cur_year = tday_list[0]
    today_str = '{0}{1}{2}'.format(cur_year, cur_month, cur_day)
    dict_m_seed = _dead_month_seed()[cur_month]
    t_seed = int(today_str)
    m_seed = int(dict_m_seed)
    init_seed = t_seed + m_seed
    domains = ""
    domain = []
    for i in range(init_i):
        seed = (idx + i + ((init_seed >> 0x18) & 0xff | (init_seed << 0x8)) + 0x65BA0642) & 0xffffffff
        s_seed = ctypes.c_int(seed).value
        domain.append(chr((abs(s_seed) % 0x19) + ord("a")))
    domain = "".join(domain)
    domains = domain
    return domains

# Server function that checks for a specific User-Agent and a hashed key in the ETage header. Watis for post and writes evidence sent from client to file.
async def DFIR_Dead_Drop_Server(request):
    dead_hdr_key = dead_dga_algorithm('key')
    dead_hsh_key = hash_keys_hosts(dead_hdr_key)
    dead_cpost_ua = "DFIR_DeadDrop UserAgent"
    dead_hdr = request.headers
    dead_rmt_ip = request.remote
    dead_ua_chk = dead_hdr.get('User-Agent')
    dead_et_chk = dead_hdr.get('ETag')
    if (dead_ua_chk == dead_cpost_ua and dead_et_chk == dead_hsh_key):
        dead_resp_data = await request.read()
        dead_file = "DFIR_Host_Evidence_" + datetime.now().strftime('%Y%m%dT%H%M%S') + ".7z"
        with open(dead_file, 'wb') as dead_w_file:
            dead_w_file.write(dead_resp_data)
            dead_w_file.close()
            print('[+] {0:s} --> DFIR DeadDrop Client has responded with Remote IP: {1:s} UserAgent: {2:s}'.format(str(datetime.now()),dead_rmt_ip,dead_ua_chk))
        return web.Response(text='DFIR Host Evidence recieved')
    else:
        return web.HTTPNotFound()

# Client function with a preset URI, and User-Agent and ETag headers. Opens and reads evidence file to be streamed to the server.
async def DFIR_Dead_Drop_Client(dead_host,dead_file):
    dead_url = dead_host + ":8081/DFIR/DeadDrop"
    dead_post_ua = "DFIR_DeadDrop UserAgent"
    dead_hdr_key = dead_dga_algorithm('key')
    dead_hsh_key = hash_keys_hosts(dead_hdr_key)
    dead_hdrs = {
        'User-Agent': dead_post_ua,
        'ETag': dead_hsh_key
        }
    try:
        with open(dead_file, 'rb') as dd_send_f:
            async with aiohttp.ClientSession() as session:
                async with session.post(dead_url, headers=dead_hdrs, data=dd_send_f) as response:
                    dead_post_resp = await response.text()
    except Exception as e:
        dead_post_resp = str(e)
    return dead_post_resp
    
if __name__ == '__main__':
    try:
        if len(sys.argv) == 1:
            print(Fore.CYAN + r"""
DeadDrop Usage:
    DeadDrop Server - python3 ./deaddrop.py --server
    DeadDrop Client - python3 ./deaddrop.py --client -h http://<ip or domain of server> -f </path/to/file/here.extension>
""")
        if len(sys.argv) > 1:
            if sys.argv[1] == '--server':
                print(Fore.RED + r"""
    ╔═══╦═══╦══╦═══╗╔═══╗───────╔╦═══╗
    ╚╗╔╗║╔══╩╣╠╣╔═╗║╚╗╔╗║───────║╠╗╔╗║
    ─║║║║╚══╗║║║╚═╝║─║║║╠══╦══╦═╝║║║║╠═╦══╦══╗
    ─║║║║╔══╝║║║╔╗╔╝─║║║║║═╣╔╗║╔╗║║║║║╔╣╔╗║╔╗║
    ╔╝╚╝║║──╔╣╠╣║║╚╗╔╝╚╝║║═╣╔╗║╚╝╠╝╚╝║║║╚╝║╚╝║
    ╚═══╩╝──╚══╩╝╚═╝╚═══╩══╩╝╚╩══╩═══╩╝╚══╣╔═╝
    ──────────────────────────────────────║║ Server
    ──────────────────────────────────────╚╝
    """)
                app = web.Application(client_max_size=0)
                app.add_routes([web.post('/DFIR/DeadDrop', DFIR_Dead_Drop_Server)]) # The URI can be changed be sure to change the client to reflect URI change.
                web.run_app(app, port=8081) # Port can be changed be sure to change client to reflect the port change.
            if sys.argv[1] == '--client' and sys.argv[2] in ('-f','-h') and sys.argv[4] in ('-f','-h'):
                print(Fore.GREEN + r"""
    ╔═══╦═══╦══╦═══╗╔═══╗───────╔╦═══╗
    ╚╗╔╗║╔══╩╣╠╣╔═╗║╚╗╔╗║───────║╠╗╔╗║
    ─║║║║╚══╗║║║╚═╝║─║║║╠══╦══╦═╝║║║║╠═╦══╦══╗
    ─║║║║╔══╝║║║╔╗╔╝─║║║║║═╣╔╗║╔╗║║║║║╔╣╔╗║╔╗║
    ╔╝╚╝║║──╔╣╠╣║║╚╗╔╝╚╝║║═╣╔╗║╚╝╠╝╚╝║║║╚╝║╚╝║
    ╚═══╩╝──╚══╩╝╚═╝╚═══╩══╩╝╚╩══╩═══╩╝╚══╣╔═╝
    ──────────────────────────────────────║║ Client
    ──────────────────────────────────────╚╝
    """)
                if sys.argv[2] == '-h':
                    dead_host = str(sys.argv[3])
                if sys.argv[2] == '-f':
                    dead_file = str(sys.argv[3])
                if sys.argv[4] == '-h':
                    dead_host = str(sys.argv[5])
                if sys.argv[4] == '-f':
                    dead_file = str(sys.argv[5])
                loop = asyncio.get_event_loop()
                dead_response = loop.run_until_complete(DFIR_Dead_Drop_Client(dead_host,dead_file))
                print('[+] {0:s} --> DFIR DeadDrop Client has finished upload. Here is the server response --> {1:s}'.format(str(datetime.now()),dead_response))
    except Exception as dd_error:
        print(dd_error)
        print(Fore.CYAN + r"""
DeadDrop Usage:
    DeadDrop Server - python3 ./deaddrop.py --server
    DeadDrop Client - python3 ./deaddrop.py --client -h http://<ip or domain of server> -f </path/to/file/here.extension>
""")
        sys.exit(1)
