# -*- coding: utf-8 -*-
# CODING=UTF8
#
# Weechat Remote Control
# ======================================================================
# Author       : Radek Valasek
# Contact      : https://github.com/reddy75/wrecon/issues
# Licence      : GPL3
# Description  : Script for control remote server
# Requirements : weechat, python3, tmate, ircrypt (script for weechat)

# GIT ................... : https://github.com/reddy75/wrecon
# LATEST RELEASE ........ : https://github.com/reddy75/wrecon/releases/latest
# BUG REPORTS ........... : https://github.com/reddy75/wrecon/issues
# IMPROVEMENT SUGGESTIONS : https://github.com/reddy75/wrecon/issues
# WIKI / HELP ........... : https://github.com/reddy75/wrecon/wiki

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

# Changelog:
# 1.18.9 - Bug fix SSH AUTOADVERTISE
# 1.18.8 - Version correction
# 1.18.7 - Fixed bug of variables (lower cases and UPPER CASEs)
#        - in commands REGISTER and UNREGISTER
# 1.18.6 - Fixed bug of variables (lower cases and UPPER CASEs)
# 1.18.5 - Fixed list command (correction of command arguments)
# 1.18.4 - Fix command ADVERTISE
# 1.18.3 - Small fix of call ADDITIONAL ADVERTISE
#        - assignment variables fix (another patch)
#        - Fix ssh call
# 1.18.2 - Small fix of call ADDITIONAL ADVERTISE
#        - assignment variables fix (another patch)
# 1.18.1 - Small fix of call ADDITIONAL ADVERTISE
#        - assignment variables fix (another patch)
# 1.18 - Small fix of call ADDITIONAL ADVERTISE
#      - assignment variables fixed
# 1.17 - Small fix of call ADDITIONAL ADVERTISE
# 1.16 - Small fix of call ADVERTISE after RENAME
# 1.15 - Small fix in HELP - REGISTER
# 1.14 - Bug fix REMOTE RENAME
# 1.13 - Bug fixes
# 1.12 - Version fix
# 1.11 - Bug fix for HELP command
# 1.10 - Command UPDATE added - New feature (check and install new version from GIT repo)
#      - Added UNIQUE HASH to all called commands
#      - Command UNREGISTER changed to UN[REGISTER]
#      - Help for UNREGISTER updated
#      - Corrected LATEST RELEASE in header of script
# 1.05 - Bug fix issue #3
# 1.04 - Bug fix issue #2
#      - Removed never used variable(s)
#      - Added autoadvertise request from local PC for non-advertised remote BOT when calling SSH
#      - Small bug fixes
# 1.03 - Update Contact field
#      - Small fixes of parts of short help
#      - Small fixes of parts of comments of code
# 1.02 - Bug fix issue #1
#        added github links into header
# 1.01 - Bug fix
# 1.00 - First release

# Purpose:
# Start 'tmate' session on remote PC over Weechat.
# - tmate session is started only for granted server(s)
# - communication between servers is accomplished over a registered IRC #Channel
# - IRC #Channel is encrypted via ircrypt
# 
# 
# Dependencies:
# Weechat, Tmate, Python3, Python3 modules - ast, base64, datetime, hashlib, os, random, string, sys, time, weechat
# 
# 
# Limitations:
# - only one IRC #Channel with IRC Server is allowed to register
# - supported platform is only linux and android (9/10 - with termux installed)
# 
# 
# Tested on platform:
# - Fedora 30/31
# - Xubuntu 18.04
# - Android 9/10 (in termux)


## FIRST START - EXAMPLE
# Connect to an IRC Server, then choice a #Channel you want to register and then
# type /wrecon register channelkey channelencryptkey
# - channelkey        - choice a string for locking your #Channel (use longest key as possible)
# - channelencryptkey - encryption of messages in channel will be encrypted by using 'ircrypt'
#
# Example of ensuring communication between your PC (Server A) and remote PC (Server B)
# - Server A have BOT ID 'abc' and BOT KEY 'def' (all is generated automatically by first run of wrecon)
# - Server B have BOT ID 'ghi' and BOT KEY 'jkl' (all is generated automatically by first run of wrecon)
#
# On Server A register remote BOT of Server B by
# /wrecon add ghi jkl
# On Server B grant remote access for remote BOT of Server A by
# /wrecon grant abc
#
# Now your wrecon is prepared to control Server B from Server A, and you can try
# on Server A start 'tmate' session on Server B by
# /wrecon ssh ghi
#
# When all was successful, for Server A will be displayed information of 'tmate'
# session established on Server B

# For short help of all commands use /wrecon help
# For detailed help of all commands use /help wrecon

#####
#
# BASIC INITIALIZATION
# try import modules for python and check version of python

global SCRIPT_NAME, SCRIPT_VERSION, SCRIPT_AUTHOR, SCRIPT_LICENSE, SCRIPT_DESC, SCRIPT_UNLOAD, SCRIPT_CONTINUE, SCRIPT_TIMESTAMP
SCRIPT_NAME      = 'wrecon'
SCRIPT_VERSION   = '1.18.9'
SCRIPT_TIMESTAMP = '20200325161009CET'
SCRIPT_AUTHOR    = 'Radek Valasek'
SCRIPT_LICENSE   = 'GPL3'
SCRIPT_DESC      = 'Weechat Remote control (WRECON)'
SCRIPT_UNLOAD    = 'wrecon_unload'

SCRIPT_CONTINUE  = True
import importlib
for import_mod in ['ast', 'base64', 'contextlib', 'datetime', 'gnupg', 'hashlib', 'json', 'os', 'random', 'shutil', 'string', 'sys', 'tarfile', 'time', 'urllib', 'weechat']:
  if type(import_mod) is str:
    try:
      import_object = importlib.import_module(import_mod, package=None)
      globals()[import_mod] = import_object
      # ~ print('[%s v%s] > module %s imported' % (SCRIPT_NAME, SCRIPT_VERSION, import_mod))
    except ImportError:
      SCRIPT_CONTINUE = False
      print('[%s v%s] > module >> %s << import error' % (SCRIPT_NAME, SCRIPT_VERSION, import_mod))
  else:
    basemodule = import_mod[0]
    import_mod.pop(0)
    for submodule in import_mod:
      try:
        import_object = importlib.import_module(basemodule, package=submodule)
        globals()[import_object] = import_object
        # ~ print('[%s v%s] > module %s:%s imported' % (SCRIPT_NAME, SCRIPT_VERSION, basemodule, submodule))
      except ImportError:
        SCRIPT_CONTINUE = False
        print('[%s v%s] > module %s:%s import error' % (SCRIPT_NAME, SCRIPT_VERSION, basemodule, submodule))
    

if sys.version_info >= (3,):
  #print('[%s v%s] > python version 3' % (SCRIPT_NAME, SCRIPT_VERSION))
  pass
else:
  SCRIPT_CONTINUE = False
  print('[%s v%s] > python version %s is not supported' % (SCRIPT_NAME, SCRIPT_VERSION, sys.version_info))

if SCRIPT_CONTINUE == False:
  # I there was issue with initialization basic modules for importing or version of python is unsupported, then
  # we write error message
  print('[%s v%s] > script not started, resolve dependencies and requirements' % (SCRIPT_NAME, SCRIPT_VERSION))
  pass
else:
  #####
  #
  # INITIALIZE SCRIP FOR WEECHAT
  
  weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, SCRIPT_UNLOAD, 'UTF-8')
  
  #####
  #
  # FUNCTIONS FOR VERIFY SIGNATURE OF FILE
  
  def f_verify_signature_file(work_directory):
    global PUBLIC_KEY
    
    verify_successful = False
    
    file_verify    = os.path.join(work_directory, 'wrecon.py')
    file_signature = os.path.join(work_directory, 'wrecon.py.sig')
    
    gpg        = gnupg.GPG()
    public_key = gpg.import_keys(PUBLIC_KEY)
    
    try:
      with open(file_signature, 'rb') as sigfile:
        verify_me = gpg.verify_file(sigfile, '%s' % file_verify)
      sigfile.close()
    finally:
      if verify_me:
        pk_content = public_key.__dict__
        vf_content = verify_me.__dict__
        fp_pk      = str(pk_content['results'][0]['fingerprint'])
        fp_vf      = str(vf_content['fingerprint'])
        if fp_pk == fp_vf:
          verify_successful = True
    
    del gpg
    del public_key
    del pk_content
    del vf_content
    
    return verify_successful

  #
  ##### END OF FUNCTIONS FOR VERIFY SIGNATURE OF FILE
  
  ####
  #
  # PUBLIC KEY
  
  global PUBLIC_KEY
  PUBLIC_KEY ='''
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBF15LsQBEADK9fJXtm6q15+InXemAPlJlUF6ZJVX1SiOsKIxSp025BfVkern
+j5uXJopOff5ctINQGFXV+ukHhBKWiSCfTb4RXegvVeQ37uzUWxyhku6WHxKuauO
KqYvS7Sco1n6uo5xeCDNVkioQo4I0OKWXpjVvw6+Ve4seeIbzQN3hSvtPLJJzbJp
r4BtHtD/YRIoiY+zJDYOn6S8agz8EXrnNk4/wmZgMp42oo1aOngq8Z06qJ8ietkQ
hccRJgEAfIt5tkvEzfeQy5J1JyD/XgA9pIZ/xSCMezgtzCv2zDoIAhxPpUq8InDy
jNjJxeNDLEFZs9BjVkc7YjaPvtrTTffutl76ivAYopiZVCYV92oWlKiwvlgxHZcA
8e5pDGFuiwZ2CccaqsOxmmmgTYkM4j3d9JWHDESz91igHhZGDZXDQpxwziJdtjxh
Imlo6sxSCkY6ao/yD+DQGeVHqGElEjW0zoXrRP8mODgTndw+q+GhgzAjkBKez4U2
c1FRvnPdO9W7Pja+VaqbVYjhEXQ69ieOZZnmYoGQNJMRV5N8bN+PiZPK+kUr3ZLj
QaM2lKD2S3XWBgy96OYslJbKIX3x1htyVXlZwrTkJsIaSvY/grbNkswoCJPzqTMo
UrPIpjuPdDN8A81q/A/cp6lT4fXN0N67DfvkkJz+A6wJC8wEPOzFS8jD8QARAQAB
tCxSYWRlayBWYWzDocWhZWsgPHJhZGVrLnZhbGFzZWsuNzVAZ21haWwuY29tPokC
YwQTAQoANhYhBEXtfg7TIRSWGjBQtGQuynjp8aa7BQJdeS7EAhsDBAsJCAcEFQoJ
CAUWAgMBAAIeAQIXgAAhCRBkLsp46fGmuxYhBEXtfg7TIRSWGjBQtGQuynjp8aa7
RLkP/0cQMbTYk/0eQQghyiyX/QVlvJ3xSbAo1BvSkpRgtt7fzERQKtxGsEtt8kaF
PQv4+qitbT+BGedXA9b738Mr/OBVuYP03cQNF+Pnk7n/sHdCRXCkM5TXN7OAmc7f
NRj8bcyIKRTjfR/v7X9hgztST54UwFgJv28zTNxehkNUdaqPtiCZSSkGwBHmr+Kf
nkKZKQzzUnJMzuuP6D240pKO4DQ4+tImbM0m2C3ofAxLeF12Rl1pygjEMSCgaRED
aBqNqDCN/QZFM7A20tbu1s7A2CxF+gsU9N45rQW6UfIQX/2KmM6QfvlTyjojWzU8
QFyNKhlhxpPL/hc2EKAg5dsgbhyHgqP1eNZnWNzjbBxgow1HvoEIl1J9ascAHMT/
vUrca8C+PJ99Qaw6XbyPN1ScR+k2O3uVS1t+4s8xzpZbL+dFfc8b+QPbJb9D91tO
zoC5oVcsE4QLMOi5DZ9ZlipQjw2qQmH0ocLITatNwpbsiRRmyj25AkBZppRCcAya
9Rsr2Sa2EuV50sLiC/hnEsV0z6opXz+NqvfCWIdXiZWfchNWmSM9QZfgerymrpEf
NUTZipu9ps+AlvixY2DOBPdpdiLeyiGaYW+lyBk+3Jn8pQlVQVCvbEFIU9Cpxk59
0JlWXMwbZeiver/ca+gXfj5bmSH7ik33L0EtpTq2Pa9EbVEOuQINBF15LvoBEADG
xaC51pbOElqLwOJsfHLZYjqB0alw5U1agygfVmJRaby5iHrBX64otGzszWE7u5Vl
G+cj3aXua/clj3vO1tIuBsOlFRimBfBxUMJ9n26rRvk9iMWhEcxfFo4VN6iBgheE
Mpix735g5WKAo9fg1o8PW7rvZBPZe7K7oEHly9MpHpTUalDEU4KHQA78S5i49Vwj
s6yxl0Bn+Pj4F1XLlJeC51udPKwt7tkhPj2j1lMQ7emuU5Sbn1rLWJWq7fNnU/e4
g5uCowzi6dLSWYl1jNRT9o545Gp7i9SPn+ur2zVgD3+ThOfOXuSYs5GWeu2bjs2I
nnXms2U8f4AJfkkwlJaM1Ma68ywoxngZw6WjQtKGLWNbkiA2L5YvMyxNy2RVOeo9
JtdfN4u93W58wr94glywxW8Mx+4VX/vKRnbwa6oApDHLHWJMfI0pFzoj6OfUGGPi
fl7kCjjUwa5FSYQcYhQCdXsWZApg25nzYFi+dKx20APvm7f4SYKd6zdS5S0YWjhC
WDBa7DKoO6rroOqi6fEletbLJ2yn+O6Q3oIG4aAkImRXEXI+gbHf4GvMzn5xtgEI
C8Epk5QTxF6TuBEaK/iQLbDWoWBUVBaVDEZkIjxmwB6CwoBzYkNEDVvvhdmyNgb+
jAao94o14tV3w2sdfB7bXTMu4gjLiTp5DmBgob4moQARAQABiQJNBBgBCgAgFiEE
Re1+DtMhFJYaMFC0ZC7KeOnxprsFAl15LvoCGwwAIQkQZC7KeOnxprsWIQRF7X4O
0yEUlhowULRkLsp46fGmu7j2D/99eWv90v5BzW1cgau8fQrZUgNpUZD8NhandtPc
bI31/fQp0uPGNG14qRYjOPxa268nmozxMT7N0p5dC9B3CM2v2ykiruz7wRuPvO9j
Py/FDotHI7JzWeFQGgsoR9+ZWtzUI+JJ/Uh4l94X6UgSR5dqJM1WokerjP6K/LGa
ird7gK+o+oy6GWgF7ANWw77sWcqUhPYM4wszQiw8tLe/RKADgZYE4ciXD5rHiImP
+tVf7bewpMYkbOgQFldEo3uzjwZlcjFbNnzPCwEIInDdeWI4Sojo2WKlFsE8Z8rV
UVv/kGAhbiZwJVnOsDkR/86fKwtDFdO1Ytga7JNgcKpLjDK+IbQdwLYuuAt/xsOw
eV2gKTK4h+xZ6RQO5xwn94JObdWAUD9ScGo9sH7oSs3d/YVAfvDKZehWRchov4Dr
5trEgTXPXUKo9m0kYop8t0GxxjfqJ2ne3xwngh90gl3E1REcz/BI7Ckm7TYmm44v
4nj7Dj4ugEbH6I49u+MIF3ra5j/fsv4EZlpvuPNJy5nvxty/NfHk2JhX+CdETBmQ
HZsQjwtkGlg74ahJtWELhJunMYJuhBJwMn1jHGtI2/AusJEtq9JOzX8rImUxoKt0
UAq1cXOx8cCFQLxap557cOszspm9RYhuo9ySvHh0Uon+bWrvrH/ksLc7YJwyZQ/c
vJ3oMrkCDQRdeS8SARAAtCC2iG+iCjZrR+45O3TPKP/HjLmrj+FZWiDEvVI7sxlF
0rEOH9lJIVFcspeyzE0LnxZHi1UvOeF/P07Lcrp+CZvkeVi6sOwDL1E5cdkoOoV+
TbVV6mm4gaIw3oAZ7PAe2fpLtu33aYtWa+SVONOp9rFnOnEJs1jB8/u806UAHmoB
HWi35OBHiYyDA5jx4HWccSxc828MqBnmbpOsniigFEyj4paW+q/7ug5I7p9aBYYs
4CqS708sodJG+MuFpOZ2+XKTYrMvdTFZLbKqD8bmSwrAaA0FIFmIw+msbhpQnsrG
/RHXyItuwZybsLcrwLfp+0WPHbr//C5d96F+a21+suajRRvqjsTBabAYGlMRw0Ly
aHxBz0lWL0UT9hjGmmgC9Fgv3UessCvNe39Smt8ZnSE+sbyRZEmnjSd2mrKAcQ8b
6iQqqO+y0YbipgIjqxBDAsjWcYbd1/MTDr4ZTev1AkJ3shxgDBPogqQXGgOOrRI0
agb5frHSIvjo7AoyTbYjnqURWG3puBxFTuuxBK33n8umMdqigJQnDUJ8gtjzXmn9
BdQ5Pejaf5zduxdiv25l0Dcq6qplryfvowtfuJeLpNQOJrWbPq4UHqjN2cUF+HwI
tjfVUiGCl441FhgkJKOAcyNUO9TqNXSL5tR08dGQ/BYqlYSCIg7dgW2XojMtvFMA
EQEAAYkCTQQYAQoAIBYhBEXtfg7TIRSWGjBQtGQuynjp8aa7BQJdeS8SAhsgACEJ
EGQuynjp8aa7FiEERe1+DtMhFJYaMFC0ZC7KeOnxpruftQ//fw9TB2D1LZ1X5e8O
Uak29qiKgzCLFL24Q4pYY9MWDlN92qWjZxxuhVGXDIsmZ6yVU25bG3D3DLxOaWEJ
GqlQaA7mMvojhABQhZWRNQO4YrLkywR6M+wW7ga5xpvvIDoy9dmo8kybptUXBjSy
C0Ad6CGE5BcmdhD5B2jwUdfDDyQx95vjw2Zn1P59SHr8klNJbZvSNwtbfbY7vMUJ
Bq1v8EoCKu7Cyc0V+GaO4N4yj+k+yCVvfBpuisyzaA8nuAErrpxCmAZISKmv4kGC
6g1RQYDHxYnbYz2/hKsMj1aLyxBrIweHWnQwA3DrL9g8EJLDDfrOVO+4Cczpoa23
GUakDBIVocEK2JCIrvfa+LYfV2FSpKsCMQhD01ZeGwRT/XqGF234Pvpg/b9/D/DH
w7WpOD31yKQdklxW9P40D4Bk76SE+Mdy0kpxynbZ7WYOvO5CBFZ4yoA1mBw7KL7m
UYanKeAcB+GFWUfm6gSarE9D5uK+7+VrQCoqQTShsRpSHCGIXXDF9tv/kz0xt3Kw
niUws8q80UVE4+LuwQqPjyxGrtMnOMKMpCjm3Nd5THtaIEFIyL098FnCt49Wn/ro
i68o63HicKAfnAqq7Chc2ruMxMY+0u3s0OS5o6aJkySzzMUgki5ipKUEGRJQFWSb
KPX4rlTJFYD/K/Hb0OM4NwaXz5Q=
=FtIt
-----END PGP PUBLIC KEY BLOCK-----
  '''
  
  #
  ##### END OF PUBLIC KEY

  #####
  #
  # FUNCTION FOR GENERATING RANDOM CHARACTERS AND NUMBERS
  
  def f_random_generator(mylength):
    lettersAndDigits = string.ascii_letters + string.digits
    return ''.join(random.choice(lettersAndDigits) for i in range(mylength))
  
  #####
  #
  # FUNCTION FOR COUNTING COMMANDS
  
  def f_command_counter():
    global WRECON_COMMAND_COUNTER
    WRECON_COMMAND_COUNTER = WRECON_COMMAND_COUNTER + 1
    if WRECON_COMMAND_COUNTER > 999:
      WRECON_COMMAND_COUNTER = 0
    return '%03d-%s' % (WRECON_COMMAND_COUNTER, f_random_generator(3))
  
  #####
  #
  # FUNCTION FOR CHECK MY NICK IS OP AND CHANNEL CAN BE UPDATE IF NECESSARY
  def f_change_modeop(data, buffer, servername, channelname):
    global WRECON_CHANNEL_KEY
    result      = 0
    resultnick  = 0
    resultchan  = 0
    resultmode  = 0
    my_nickname = weechat.info_get('irc_nick', servername)
    infolist    = weechat.infolist_get('irc_nick', '', '%s,%s' % (servername, channelname))
    while weechat.infolist_next(infolist):
      found_nickname = weechat.infolist_string(infolist, 'name')
      if my_nickname == found_nickname:
        my_prefix   = weechat.infolist_string(infolist, 'prefix')
        my_prefixes = weechat.infolist_string(infolist, 'prefixes')
        if '@' in my_prefixes:
          resultnick = 1
    weechat.infolist_free(infolist)

    infolist   = weechat.infolist_get('irc_channel', '', '%s,%s' % (servername, channelname))
    while weechat.infolist_next(infolist):
      my_channel_name = weechat.infolist_string(infolist, 'name')
      my_channel_key  = weechat.infolist_string(infolist, 'key')
      my_channel_mode = weechat.infolist_string(infolist, 'modes')
      if my_channel_name == channelname:
        if not WRECON_CHANNEL_KEY in my_channel_mode:
          resultchan = 1
        if not 'k' in my_channel_mode:
          resultmode = 1
        
    weechat.infolist_free(infolist)
    
    if resultnick == 1:
      if resultmode == 1 or resultchan == 1:
        weechat.command(buffer, '/mode %s -n+sk %s' % (channelname, WRECON_CHANNEL_KEY))
    return result
  
  #####
  #
  # FUNCTION GET HASH OF A STRING
  global uniq_hash
  uniq_hash = ''
  
  def f_get_hash(mystring):
    result = hashlib.md5(mystring.encode())
    return str(result.hexdigest())
  
  #####
  #
  # FUNCTION ENCRYPT AND DECTRYPT STRING
  # ENCRYPT
  
  def f_encrypt_string(mystring, encryptkey):
    xkey = encryptkey
    while len(mystring) > len(encryptkey):
      encryptkey += xkey
    out = []
    for i in range(len(mystring)):
      k_c = mystring[i % len(mystring)]
      o_c = chr((ord(encryptkey[i]) + ord(k_c)) % 256)
      out.append(o_c)
    return base64.urlsafe_b64encode(''.join(out).encode()).decode()
  #
  # DECRYPT
  #
  def f_decrypt_string(mystring, encryptkey):
    xkey = encryptkey
    while len(mystring) > len(encryptkey):
      encryptkey += xkey
    out = []
    enc = base64.urlsafe_b64decode(mystring).decode()
    for i in range(len(enc)):
      k_c = encryptkey[i % len(encryptkey)]
      d_c = chr((256 + ord(enc[i]) - ord(k_c)) % 256)
      out.append(d_c)
    return ''.join(out)

  #
  #### END FUNCTION ENCRYPT AND DECTRYPT STRING
  
  #####
  #
  # FUNCTION CHECK AND UPDATE
  
  def f_check_for_new_version(data, buffer):
    global SCRIPT_VERSION
    import urllib.request
    update_me = False
    f_message_simple(data, buffer, 'CHECKING FOR UPDATE')

    actual_version = SCRIPT_VERSION.split(' ')[0]
    latest_release = 'checking...'
    update_result  = False
    base_name      = 'reddy75/wrecon'
    base_url       = 'https://github.com/%s/archive' % base_name
    base_api       = 'https://api.github.com/repos/%s/releases/latest' % base_name
    
    f_message_simple(data, buffer, 'ACTUAL VERSION  : %s' % actual_version)
    
    error_get  = False
    try:
      url_data = urllib.request.urlopen(base_api)
    except urllib.error.HTTPError as e:
      error_get  = True
      error_data = e.__dict__
    except urllib.error.URLerror as e:
      error_get  = True
      error_data = e.__dict__
    except urllib.error.ContentTooShortError() as e:
      error_get  = True
      error_data = e.__dict__
    
    if error_get == True:
      out_err_msg = []
      out_err_msg.append('AN ERROR OCCURED DURING CHECK OF LATEST VERSION FROM GITHUB')
      out_err_msg.append('REQUESTED URL : %s' % base_api)
      out_err_msg.append('ERROR CODE    : %s' % error_data['code'])
      out_err_msg.append('ERROR MESSAGE : %s' % error_data['msg'])
      f_message(data, buffer, 'UPDATE ERROR', out_err_msg)
    else:
      get_data       = json.loads(url_data.read().decode('utf8'))
      latest_release = get_data['tag_name'].split('v')[1]
      
      f_message_simple(data, buffer, 'LATEST RELEASE  : %s' % latest_release)
      
      if actual_version >= latest_release:
        f_message_simple(data, buffer, 'WRECON IS UP TO DATE')
      else:
        archive_file   = '%s.tar.gz' % latest_release
        download_url   = '%s/%s' % (base_url, archive_file)
        
        out_msg = []
        out_msg.append('DOWNLOAD FILE   : %s' % download_url)
        
        f_message(data, buffer, 'FOUND NEW RELEASE', out_msg)
        extract_subdir = 'wrecon-%s' % latest_release
        update_me = [latest_release, archive_file, download_url, extract_subdir]
    return update_me
    
  
  def f_check_and_update(data, buffer):
    update_result = 'NOT UPDATED'
    # First check new version is available
    check_result = f_check_for_new_version(data, buffer)
    # When we receive new data, we will try download, extract, check signed file, install new file and restart wrecon
    if not check_result == False:
      latest_release, archive_file, download_url, extract_subdir  = check_result
      env_vars = os.environ
      # ~ for env_var in env_vars.keys():
        # ~ f_message_simple(data, buffer, '%32s : %s' % (env_var, env_vars[env_var]))
        
      download_dir = '%s/%s' % (env_vars['HOME'], 'wrecon-update')
      
      # ~ f_message_simple(data, buffer, 'DOWNLOAD DIR : %s' % download_dir)
      
      download_dir_exist = False
      if not os.path.exists(os.path.join(download_dir)):
        try:
          os.mkdir(os.path.join(download_dir))
          download_dir_exist = True
        except OSError as e:
          f_message(data, buffer, 'OS ERROR', ['Unable create download directyr'])
      
      if not os.path.isdir(os.path.join(download_dir)):
        f_message(data, buffer, 'OS ERROR', ['Unable create download directyr'])
      else:
        start_download = False
        download_file = os.path.join(download_dir, archive_file)
        f_message_simple(data, buffer, 'DESTINATION     : %s' % download_file)
        if not os.path.exists(download_file):
          start_download = True
        else:
          if os.path.isfile(download_file):
            try:
              os.remove(download_file)
              start_download = True
            except OSError as e:
              f_message(data, buffer, 'OS ERROR', ['Destination file exist, but can not be removed. Please clean up.'])
          else:
            f_message(data, buffer, 'OS ERROR', ['Destination path exist, check your system and clean up.'])
        
        if start_download == True:
          successful_download = False
          try:
            #
            # DOWNLOAD NEW FILE
            #
            import urllib.request
            with urllib.request.urlopen(download_url) as response, open(download_file, 'wb') as out_file:
              shutil.copyfileobj(response, out_file)
            out_file.close()
            f_message_simple(data, buffer, 'DOWNLOAD STATUS : SUCCESSFUL')
            successful_download = True
          except urllib.error.URLerror as e:
            error_get  = True
            error_data = e.__dict__
          except urllib.error.ContentTooShortError() as e:
            error_get  = True
            error_data = e.__dict__
          
          if successful_download == False:
            f_message_simple(data, buffer, 'DOWNLOAD STATUS : FAILED')
            out_err_msg = []
            out_err_msg.append('AN ERROR OCCURED DURING DOWNLOAD OF FILE FROM GITHUB')
            out_err_msg.append('REQUESTED URL : %s' % download_url)
            out_err_msg.append('ERROR CODE    : %s' % error_data['code'])
            out_err_msg.append('ERROR MESSAGE : %s' % error_data['msg'])
            f_message(data, buffer, 'UPDATE ERROR', out_err_msg)
          else:
            #
            # EXTRACT ARCHIVE
            #
            current_cwd = os.getcwd()
            os.chdir(download_dir)
            error_extract = False
            try:
              extract_me  = tarfile.open(archive_file)
              out_message = extract_me.extractall()
            except TarError as e:
              error_extract = True
              error_message = e.__dict__
            except ReadError as e:
              error_extract = True
              error_message = e.__dict__
            except CompressionError as e:
              error_extract = True
              error_message = e.__dict__
            except StreamError as e:
              error_extract = True
              error_message = e.__dict__
            except ExtractError as e:
              error_extract = True
              error_message = e.__dict__
            except HeaderError as e:
              error_extract = True
              error_message = e.__dict__
              
            if error_extract == True:
              out_msg = []
              out_msg.append('EXTRACT STATUS  : FAILED')
              out_msg.append('ERROR MESSAGE   : %s' % error_message)
              f_message(data, buffer, 'UPDATE ERROR', out_msg)
            else:
              f_message_simple(data, buffer, 'EXTRACT STATUS  : SUCCESSFUL')
              work_path = os.path.join(download_dir, extract_subdir)
              os.chdir(work_path)
              #
              # VERIFY SCRIPT FILE IS SIGNED BY AUTHOR
              #
              verify_successful = f_verify_signature_file(work_path)
              if verify_successful == False:
                f_message_simple(data, buffer, 'VERIFICATION    : FAILED')
              else:
                f_message_simple(data, buffer, 'VERIFICATION    : SUCCESSFUL')
                #
                # INSTALLATION OF NEW SCRIPT WHICH WAS VERIFIED SUCCESSFULLY
                #
                destination_dir  = weechat.string_eval_path_home('%h', {}, {}, {})
                destination_dir  = str(os.path.join(destination_dir, 'python'))
                destination_file = str(os.path.join(destination_dir, 'wrecon.py'))
                source_file      = str(os.path.join(work_path, 'wrecon.py'))
                copy_err         = False
                try:
                  copy_result = shutil.copyfile(source_file, destination_file, follow_symlinks=True)
                  f_message_simple(data, buffer, 'INSTALLATION    : SUCCESSFUL')
                except OSError as e:
                  copy_err = True
                  err_msg = e.__dict__
                  err_msg = e
                except shutil.SameFileError as e:
                  copy_err = True
                  err_msg = e.__dict__
                
                if copy_err == True:
                  out_msg = []
                  out_msg.append('INSTALLATION    : FAILED')
                  out_msg.append('ERROR MESSAGE   : %s' % err_msg)
                  f_message(data, buffer, 'INSTALLATION ERROR', out_msg)
                else:
                  #
                  # AFTER SUCCESSFUL INSTALLATION RESTART WEECAHT
                  #
                  f_message_simple(data, buffer, 'RESTARTING WRECON...')
                  weechat.command(buffer, '/wait 2s /script reload wrecon.py')
                
            os.chdir(current_cwd)
    return update_result
  
  #
  ##### END FUNCTION CHECK AND UPDATE
  
  #####
  #
  # FUNCTIONS FOR LOCAL MESSAGES
  # without header
  
  def f_message_simple(data, buffer, message):
    global SCRIPT_NAME
    weechat.prnt(buffer, '[%s]\t%s' % (SCRIPT_NAME, message))
    return weechat.WEECHAT_RC_OK
  #
  # with header
  #
  def f_message(data, buffer, message_tag, message):
    global WRECON_BOT_NAME, WRECON_BOT_ID
    f_message_simple(data, buffer, '--- %s (%s %s) ---' % (message_tag, WRECON_BOT_NAME, WRECON_BOT_ID))
    for my_index in range(0, len(message), 1):
      f_message_simple(data, buffer, '%s' % (message[my_index]))
    return weechat.WEECHAT_RC_OK
  #
  ##### END FUNCTIONS FOR LOCAL MESSAGES
  
  
  #####
  #
  # FUNCTION GET BUFFERS AND BUFFER OF REGISTERED CHANNEL
  
  def f_get_buffers():
    WRECON_BUFFERS  = {}
    infolist_buffer = weechat.infolist_get('buffer', '', '')
    while weechat.infolist_next(infolist_buffer):
      buffer_pointer              = weechat.infolist_pointer(infolist_buffer, 'pointer')
      buffer_name                 = weechat.buffer_get_string(buffer_pointer, 'localvar_name')
      WRECON_BUFFERS[buffer_name] = buffer_pointer
    weechat.infolist_free(infolist_buffer)
    return WRECON_BUFFERS
  
  def f_get_buffer_channel():
    global WRECON_SERVER, WRECON_CHANNEL
    wrecon_buffer_name = '%s.%s' % (WRECON_SERVER, WRECON_CHANNEL)
    WRECON_BUFFERS     = f_get_buffers()
    if wrecon_buffer_name in WRECON_BUFFERS:
      return WRECON_BUFFERS[wrecon_buffer_name]
    else:
      return ''
  
  #
  ##### END FUNCTION GET BUFFERS AND BUFFER OF REGISTERED CHANNEL
  
  #####
  #
  # FUNCTIONS ADD/DEL/SAVE CHANNEL TO/FROM irc.server.<servername>.autojoin
  
  # FUNCTION ADD CHANNEL TO AUTOJOIN
  
  def f_setup_autojoin_add(buffer, WRECON_SERVER, new_channel):
    save_setup              = False
    wrecon_channel_autojoin = weechat.string_eval_expression("${irc.server.%s.autojoin}" % (WRECON_SERVER), {}, {}, {})
    wrecon_chan_key         = '${sec.data.wrecon_channel_key}'
    my_channels             = wrecon_channel_autojoin.split(' ')[0].split(',')
    my_channels_keys        = wrecon_channel_autojoin.split(' ')[1].split(',')
    
    if not new_channel in my_channels:
      my_channels.append(new_channel)
      my_channels_keys.append(wrecon_chan_key)
      f_setup_autojoin_save(buffer, my_channels, my_channels_keys)
      save_setup = True
    else:
      # Find index of my registered channel and test it have properly setup secure key
      my_channel_index = [i for i, elem in enumerate(my_channels) if new_channel in elem]
      for my_index in my_channel_index:        
        if not wrecon_chan_key in my_channels_keys[my_index]:
          my_channels_keys[my_index] = wrecon_chan_key
          save_setup = True
      if save_setup == True:
        f_setup_autojoin_save(buffer, my_channels, my_channels_keys)
    return save_setup
  
  # FUNCTION DEL CHANNEL FROM AUTOJOIN
  
  def f_setup_autojoin_del(buffer, WRECON_SERVER, del_channel):
    save_setup = False
    wrecon_channel_autojoin = weechat.string_eval_expression("${irc.server.%s.autojoin}" % (WRECON_SERVER), {}, {}, {})
    wrecon_chan_key         = '${sec.data.wrecon_channel_key}'
    my_channels             = wrecon_channel_autojoin.split(' ')[0].split(',')
    my_channels_keys        = wrecon_channel_autojoin.split(' ')[1].split(',')
    
    if del_channel in my_channels:
      # Find index of my registered channel
      my_channel_index = [i for i, elem in enumerate(my_channels) if del_channel in elem]
      for my_index in my_channel_index:
        del my_channels[my_index]
        del my_channels_keys[my_index]
      f_setup_autojoin_save(buffer, my_channels, my_channels_keys)
      save_setup = True
    return save_setup
  
  # FUNCTION SAVE DATA FOR AUTOJOIN, called only when data was changed
  
  def f_setup_autojoin_save(buffer, my_channels, my_channels_keys):
    export_channels = ','.join(map(str, my_channels))
    export_keys     = ','.join(map(str, my_channels_keys))
    export_data     = '%s %s' % (export_channels, export_keys)
    weechat.command(buffer, '/set irc.server.%s.autojoin %s' % (WRECON_SERVER, export_data))
    return
  
  #
  ##### END FUNCTIONS ADD/REMOVE/SAVE CHANNEL TO/FROM irc.server.<servername>.autojoin
  
  #####
  #
  # FUNCTIONS AUTOCONNECT
  # 1) test we are connected to registered server - (connect automatically)
  # 2) test we are joined to registered channel - (join automatically)
  
  def f_autoconnect():
    global WRECON_SERVER, WRECON_CHANNEL
    if WRECON_SERVER and WRECON_CHANNEL:
      if f_get_status_server() == 0:
        f_autoconnect_server()
      else:
        v_buffer_server = f_get_buffers()
        f_autoconnect_channel(v_buffer_server['server.%s' % (WRECON_SERVER)])
    return weechat.WEECHAT_RC_OK
  
  def f_get_status_server():
    global WRECON_SERVER
    infolist_server = weechat.infolist_get('irc_server', '', '')
    server_status   = {}
    while  weechat.infolist_next(infolist_server):
      server_name                = weechat.infolist_string(infolist_server, 'name')
      server_stat                = weechat.infolist_integer(infolist_server, 'is_connected')
      server_status[server_name] = server_stat
    weechat.infolist_free(infolist_server)
    
    if WRECON_SERVER in server_status:
      return server_status[WRECON_SERVER]
    else:
      return '0'
  
  def f_get_status_channel():
    global WRECON_SERVER, WRECON_CHANNEL
    infolist_channel  = weechat.infolist_get('irc_channel', '', WRECON_SERVER)
    channel_status    = {}
    do_record         = False
    while weechat.infolist_next(infolist_channel):
      channel_fields = weechat.infolist_fields(infolist_channel).split(",")
      for channel_field in channel_fields:
        (channel_field_type, channel_field_name) = channel_field.split(':', 1)
        if channel_field_type == 'i':
          channel_field_value = weechat.infolist_integer(infolist_channel, channel_field_name)
        elif channel_field_type == 'p':
          channel_field_value = weechat.infolist_pointer(infolist_channel, channel_field_name)
        elif channel_field_type == 's':
          channel_field_value = weechat.infolist_string(infolist_channel, channel_field_name)
        elif channel_field_type == 'b':
          channel_field_value = weechat.infolist_buffer(infolist_channel, channel_field_name)
        elif channel_field_type == 't':
          channel_field_value = weechat.infolist_time(infolist_channel, channel_field_name)
        else:
          channel_field_value = 'N/A'
        if channel_field_name == 'buffer_short_name' and channel_field_value == WRECON_CHANNEL:
          do_record = True
        elif channel_field_name == 'buffer_short_name' and channel_field_value != WRECON_CHANNEL:
          do_record = False
        if do_record == True:
          channel_status[channel_field_name] = channel_field_value
    weechat.infolist_free(infolist_channel)

    if 'nicks_count' in channel_status:
      return channel_status['nicks_count']
    else:
      return 0
  
  def f_get_server_setup():
    global WRECON_SERVER
    infolist_server = weechat.infolist_get('irc_server', '', '')
    server_status   = {}
    while weechat.infolist_next(infolist_server):
      server_fields = weechat.infolist_fields(infolist_server).split(",")
      for server_field in server_fields:
        (server_field_type, server_field_name) = server_field.split(':', 1)
        if server_field_type == 'i':
          server_field_value = weechat.infolist_integer(infolist_server, server_field_name)
        elif server_field_type == 'p':
          server_field_value = weechat.infolist_pointer(infolist_server, server_field_name)
        elif server_field_type == 's':
          server_field_value = weechat.infolist_string(infolist_server, server_field_name)
        elif server_field_type == 'b':
          server_field_value = weechat.infolist_buffer(infolist_server, server_field_name)
        elif server_field_type == 't':
          server_field_value = weechat.infolist_time(infolist_server, server_field_name)
        else:
          server_field_value = 'N/A'
        f_message_simple('', '', 'SETUP - %s - %s : %s' % (WRECON_SERVER, server_field_name, server_field_value))
    weechat.infolist_free(infolist_server)
    return server_status
    
  def f_autoconnect_server():
    global WRECON_SERVER
    weechat.command('', '/connect %s' % (WRECON_SERVER))
    WRECON_HOOK_CONNECT = weechat.hook_timer(1*1000, 0, 20, 'f_autoconnect_server_status', '')
    return weechat.WEECHAT_RC_OK
  
  def f_autoconnect_server_status(arg1, arg2):
    global WRECON_SERVER
    if f_get_status_server() == 1:
      weechat.unhook(WRECON_HOOK_CONNECT)
      WRECON_BUFFERS = f_get_buffers()
      f_autoconnect_channel(WRECON_BUFFERS['server.%s' % (WRECON_SERVER)])
    return weechat.WEECHAT_RC_OK
  
  def f_autoconnect_channel(buffer):
    global WRECON_CHANNEL, WRECON_CHANNEL_KEY, WRECON_HOOK_JOIN, WRECON_SERVER 
    weechat.command(buffer, '/join %s %s' % (WRECON_CHANNEL, WRECON_CHANNEL_KEY))
    WRECON_HOOK_JOIN = weechat.hook_timer(1*1000, 0, 5, 'f_autoconnect_channel_status', '')
  
  def f_autoconnect_channel_status(arg1, arg2):
    global WRECON_HOOK_JOIN, WRECON_AUTO_ADVERTISED, WRECON_HOOK_BUFFER, WRECON_BUFFER_CHANNEL, SCRIPT_CALLBACK_BUFFER
    
    if arg2 == '0':
      weechat.unhook(WRECON_HOOK_JOIN)
    
    if f_get_status_channel() > 0:
      weechat.unhook(WRECON_HOOK_JOIN)
      if WRECON_AUTO_ADVERTISED == False:
        f_buffer_hook()
        f_autoconnect_channel_mode(WRECON_BUFFER_CHANNEL)
        command_advertise('', WRECON_BUFFER_CHANNEL, '', '', '', '')
        WRECON_AUTO_ADVERTISED = True
    return weechat.WEECHAT_RC_OK
  
  def f_autoconnect_channel_mode(buffer):
    global WRECON_CHANNEL, WRECON_CHANNEL_KEY, WRECON_SERVER
    f_change_modeop('', buffer, WRECON_SERVER, WRECON_CHANNEL)
    f_change_buffer_title()
    return weechat.WEECHAT_RC_OK
  
  #
  ##### END FUNCTIONS AUTOCONNECT
  
  #####
  #
  # FUNCTION GET NICK INFORMATION
  
  def f_get_nick_info(tags, prefix):
    v_nickname     = tags[3].split('_')
    v_hostname     = tags[4].split('_')
    actual_datetime = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    output_value    = '%s|%s|%s|%s' % (v_nickname[1], v_hostname[1], prefix, actual_datetime)
    return output_value
  
  #
  ##### END FUNCTION GET NICK INFORMATION
  
  #####
  #
  # FUNCTION CHANGE BUFFER TITLE
  
  def f_change_buffer_title():
    global WRECON_SERVER, WRECON_CHANNEL, WRECON_BOT_NAME, WRECON_BOT_ID, WRECON_BUFFER_CHANNEL
    weechat.buffer_set(WRECON_BUFFER_CHANNEL, 'title', 'Weechat Remote control - %s - %s - %s [%s]' % (WRECON_SERVER, WRECON_CHANNEL, WRECON_BOT_NAME, WRECON_BOT_ID))
    return weechat.WEECHAT_RC_OK
  
  #
  ##### END FUNCTION CHANGE BUFFER TITLE
  
  #####
  #
  # INITIALIZATION OF BASIC VARIABLES FOR BOT
  
  global WRECON_DEFAULT_BOTNAMES, WRECON_BOT_NAME, WRECON_BOT_ID, WRECON_BOT_KEY
  WRECON_DEFAULT_BOTNAMES = ['anee', 'anet', 'ann', 'annee', 'annet', 'bob', 'brad', 'don', 'fred', 'freddie', 'john', 'mia', 'moon', 'pooh', 'red', 'ron', 'ronnie', 'shark', 'ted', 'teddy', 'zed', 'zoe', 'zombie']
  WRECON_BOT_NAME         = weechat.string_eval_expression("${sec.data.wrecon_bot_name}",{},{},{})
  WRECON_BOT_ID           = weechat.string_eval_expression("${sec.data.wrecon_bot_id}",{},{},{})
  WRECON_BOT_KEY          = weechat.string_eval_expression("${sec.data.wrecon_bot_key}",{},{},{})
  #
  # Choice default BOT NAME if not exist and save it
  #
  if not WRECON_BOT_NAME:
    WRECON_BOT_NAME = random.choice(WRECON_DEFAULT_BOTNAMES)
    weechat.command('','/secure set WRECON_BOT_NAME %s' % (WRECON_BOT_NAME))
  #
  #  Generate BOT ID if not exit and save it
  #
  if not WRECON_BOT_ID:
    WRECON_BOT_ID = f_random_generator(16)
    weechat.command('','/secure set WRECON_BOT_ID %s' % (WRECON_BOT_ID))
  #
  # Generate BOT KEY if not exist and save it
  #
  if not WRECON_BOT_KEY:
    WRECON_BOT_KEY = f_random_generator(64)
    weechat.command('','/secure set WRECON_BOT_KEY %s' % (WRECON_BOT_KEY))
  
  #
  #
  ##### BOT INITIALIZATION IS DONE
  
  # ~ mytext      = 'a toto je test'
  # ~ mymessage   = f_encrypt_string(mytext, WRECON_BOT_KEY)
  # ~ print('TEST : %s' % (mymessage))
  
  # ~ mymessage2  = f_decrypt_string(mymessage, WRECON_BOT_KEY)
  # ~ print('TEST : %s' % (mymessage2))
  
  #####
  #
  # INITIALIZATION OF BASIC VARIABLES FOR SERVER AND CHANNEL
  
  global WRECON_SERVER, WRECON_CHANNEL, WRECON_CHANNEL_KEY, WRECON_CHANNEL_ENCRYPTION_KEY, WRECON_BUFFERS, WRECON_BUFFER_CHANNEL, WRECON_COMMAND_COUNTER, WRECON_AUTO_ADVERTISED, WRECON_BUFFER_HOOKED
  WRECON_SERVER                 = weechat.string_eval_expression("${sec.data.wrecon_server}",{},{},{})
  WRECON_CHANNEL                = weechat.string_eval_expression("${sec.data.wrecon_channel}",{},{},{})
  WRECON_CHANNEL_KEY            = weechat.string_eval_expression("${sec.data.wrecon_channel_key}",{},{},{})
  WRECON_CHANNEL_ENCRYPTION_KEY = weechat.string_eval_expression("${sec.data.wrecon_channel_encryption_key}",{},{},{})
  WRECON_BUFFERS                = {}
  WRECON_BUFFER_CHANNEL         = ''
  WRECON_COMMAND_COUNTER        = 0
  WRECON_AUTO_ADVERTISED        = False
  WRECON_BUFFER_HOOKED          = False
  
  #####
  #
  # BASIC VARIABLES OF REGISTERED REMOTE BOTS
  #
  # control   - bots you can control remotely on remote system
  #              table contain BOT IDs and it's BOT KEYs
  #
  # GRANTED    - bots from remote system can control your system (you grant controol of your system)
  #              table contain only BOT IDs
  #
  # VERIFIED   - runtime variable of bots from remote system can control your system only after verification
  #              table contain BOT IDs and additional info from irc_channel of related NICK
  #              in case information of remote NICK will be changed, then new verification will be triggered
  #
  # ADVERTISED - runtime variable of bots which has been advertised in channel, it is only informational and for internal purpose to
  #              have actual state
  #              table contain BOT IDs and BOT NAMEs only
  
  global WRECON_REMOTE_BOTS_CONTROL, WRECON_REMOTE_BOTS_GRANTED, WRECON_REMOTE_BOTS_VERIFIED, WRECON_REMOTE_BOTS_ADVERTISED
  WRECON_REMOTE_BOTS_CONTROL    = weechat.string_eval_expression("${sec.data.wrecon_remote_bots_control}",{},{},{})
  WRECON_REMOTE_BOTS_GRANTED    = weechat.string_eval_expression("${sec.data.wrecon_remote_bots_granted}",{},{},{})
  WRECON_REMOTE_BOTS_VERIFIED   = {}
  WRECON_REMOTE_BOTS_ADVERTISED = {}
  
  if WRECON_REMOTE_BOTS_CONTROL:
    WRECON_REMOTE_BOTS_CONTROL = ast.literal_eval(WRECON_REMOTE_BOTS_CONTROL)
  else:
    WRECON_REMOTE_BOTS_CONTROL = {}
  
  if WRECON_REMOTE_BOTS_GRANTED:
    WRECON_REMOTE_BOTS_GRANTED = ast.literal_eval(WRECON_REMOTE_BOTS_GRANTED)
  else:
    WRECON_REMOTE_BOTS_GRANTED = {}
  
  #####
  #
  # INITIALIZE FUNCTIONAL VARIABLES FOR SCRIPT
  
  global SCRIPT_COMMAND_CALL, SCRIPT_ARGS, SCRIPT_ARGS_DESCRIPTION, SCRIPT_COMPLETION, SCRIPT_CALLBACK, COLOR_TEXT, SCRIPT_ARGS_DESCRIPTION, COMMAND_IN_BUFFER, SCRIPT_BUFFER_CALL
  SCRIPT_COMMAND_CALL     = {}
  SCRIPT_BUFFER_CALL      = {}
  SCRIPT_ARGS             = ''
  SCRIPT_ARGS_DESCRIPTION = ''
  SCRIPT_COMPLETION       = ''
  SCRIPT_CALLBACK         = ''
  COMMAND_IN_BUFFER       = 'WRECON-CMD>'
  COLOR_TEXT              = {
  'bold'       : weechat.color('bold'),
  'nbold'      : weechat.color('-bold'),
  'italic'     : weechat.color('italic'),
  'nitalic'    : weechat.color('-italic'),
  'underline'  : weechat.color('underline'),
  'nunderline' : weechat.color('-underline')}
  SCRIPT_ARGS_DESCRIPTION = '''
  %(bold)s%(underline)sWeechat Remote control (WRECON) commands and options:%(nunderline)s%(nbold)s
  ''' % COLOR_TEXT

  #####
  #
  # INITIALIZE HOOK VARIABLES FOR WHOLE SCRIPT
  
  global WRECON_HOOK_COMMAND, WRECON_HOOK_CONNECT, WRECON_HOOK_JOIN, WRECON_HOOK_BUFFER, WRECON_HOOK_LOCAL_COMMAND
  WRECON_HOOK_COMMAND        = ''
  WRECON_HOOK_CONNECT        = ''
  WRECON_HOOK_JOIN           = ''
  WRECON_HOOK_BUFFER         = ''
  WRECON_HOOK_LOCAL_COMMAND = ''


  #####
  #
  # COMMANDS - ALL COMMANDS
  
  #####
  #
  # COMMAND ADD REMOTE BOT YOU WILL control
  
  def command_add_controled_bot(data, buffer, NULL1, NULL2, cmd_hash, args):
    global WRECON_REMOTE_BOTS_CONTROL
    v_err       = False
    v_err_topic = 'ADD ERROR'
    if len(args) >= 2:
      new_remote_bot_id  = args[0]
      new_remote_bot_key = args[1]
      if len(args) >= 3:
        args.pop(0)
        args.pop(0)
        new_remote_bot_note = ' '.join(map(str, args))
      else:
        new_remote_bot_note = ''
      if new_remote_bot_id in WRECON_REMOTE_BOTS_CONTROL:
        f_message(data, buffer, v_err_topic, ['ALREADY ADDED. First DEL, then ADD.'])
      else:
        WRECON_REMOTE_BOTS_CONTROL[new_remote_bot_id] = [new_remote_bot_key, new_remote_bot_note]
        weechat.command(buffer, '/secure set WRECON_REMOTE_BOTS_CONTROL %s' % (WRECON_REMOTE_BOTS_CONTROL))
        f_message_simple(data, buffer, 'BOT SUCCESSFULLY ADDED')
    else:
      v_err = True
    if v_err == True:
      if args:
        f_message(data, buffer, v_err_topic, ['INCORRECT NUMBER OF ARGUMENTS > 2 expected.'])
      else:
        f_message(data, buffer, v_err_topic, ['MISSING ARGUMENTS > 2 expected.'])
    return weechat.WEECHAT_RC_OK
  
  SCRIPT_ARGS                = SCRIPT_ARGS + ' | [ADD <botid> <botkey> [note]]'
  SCRIPT_ARGS_DESCRIPTION    = SCRIPT_ARGS_DESCRIPTION + '''
  %(bold)s%(italic)s--- ADD <botid> <botkey> [note]%(nitalic)s%(nbold)s
  Add remote bot for your control. By command ADVERTISE you will know %(italic)sbotid%(nitalic)s, but the %(italic)sbotkey%(nitalic)s you need receive by safe way.''' % COLOR_TEXT + '''
  Opposite of command ADD is command DEL.
    /wrecon ADD %s %s
    /wrecon ADD %s %s %s
    ''' % (f_random_generator(16), f_random_generator(64), f_random_generator(16), f_random_generator(64), random.choice(WRECON_DEFAULT_BOTNAMES))
  SCRIPT_COMPLETION          = SCRIPT_COMPLETION + ' || ADD'
  SCRIPT_COMMAND_CALL['add'] = command_add_controled_bot
  
  #
  ##### END COMMAND ADD REMOTE BOT YOU WILL control
  

  #####
  #
  # COMMAND ADVERTISE
  
  global BUFFER_CMD_ADV_EXE, BUFFER_CMD_ADV_REP, BUFFER_CMD_ADV_ERR, BUFFER_CMD_ADA_EXE, BUFFER_CMD_ADA_REP
  BUFFER_CMD_ADV_EXE = '%sE-ADV' % (COMMAND_IN_BUFFER)
  BUFFER_CMD_ADV_REP = '%sADV-R' % (COMMAND_IN_BUFFER)
  BUFFER_CMD_ADV_ERR = '%sADV-E' % (COMMAND_IN_BUFFER)
  BUFFER_CMD_ADA_EXE = '%sE-ADA' % (COMMAND_IN_BUFFER)
  BUFFER_CMD_ADA_REP = '%sADA-R' % (COMMAND_IN_BUFFER)
  
  def command_advertise(data, buffer, NULL1, NULL2, cmd_hash, args):
    global BUFFER_CMD_EADV, BUFFER_CMD_ADV_REP, WRECON_BOT_ID, uniq_hash, WRECON_BOT_NAME, SCRIPT_VERSION, SCRIPT_TIMESTAMP
    uniq_hash = f_command_counter()
    # PROTOCOL: COMMAND TO_BOTID|HASH FROM_BOTID HASH [DATA]
    
    global WRECON_SERVER, WRECON_CHANNEL
    f_change_modeop(data, buffer, WRECON_SERVER, WRECON_CHANNEL)
    
    weechat.command(buffer, '%s %s %s %s v%s %s' % (BUFFER_CMD_ADV_EXE, uniq_hash, WRECON_BOT_ID, uniq_hash, SCRIPT_VERSION, SCRIPT_TIMESTAMP))
    return weechat.WEECHAT_RC_OK
  
  SCRIPT_ARGS                      = SCRIPT_ARGS + ' | [ADV[ERTISE]]'
  SCRIPT_ARGS_DESCRIPTION          = SCRIPT_ARGS_DESCRIPTION + '''
  %(bold)s%(italic)s--- ADV[ERTISE]%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
  Show your BOT ID in Channel and also other bots will show their IDs
    /wrecon ADV
    /wrecon ADVERTISE
  '''
  SCRIPT_COMPLETION                = SCRIPT_COMPLETION + ' || ADV || ADVERTISE'
  SCRIPT_COMMAND_CALL['adv']       = command_advertise
  SCRIPT_COMMAND_CALL['advertise'] = command_advertise
  
  def reply_advertise(data, buffer, tags, prefix, args):
    global BUFFER_CMD_ADV_REP, WRECON_BOT_ID, WRECON_BOT_NAME, SCRIPT_VERSION, SCRIPT_TIMESTAMP
    # PROTOCOL: COMMAND TO_BOTID|HASH FROM_BOTID HASH [DATA]
    v_check_is_hash       = args[0]
    v_remote_bot_id       = args[1]
    v_remote_bot_hash_cmd = args[2]
    if v_check_is_hash == v_remote_bot_hash_cmd:
      weechat.command(buffer, '%s %s %s %s %s [v%s %s]' % (BUFFER_CMD_ADV_REP, v_remote_bot_id, WRECON_BOT_ID, v_remote_bot_hash_cmd, WRECON_BOT_NAME, SCRIPT_VERSION, SCRIPT_TIMESTAMP))
    else:
      global BUFFER_CMD_ADV_ERR
      weechat.command(buffer, '%s %s %s %s [v%s %s] ERROR - PROTOCOL VIOLATION' % (BUFFER_CMD_ADV_ERR, v_remote_bot_id, WRECON_BOT_ID, v_remote_bot_hash_cmd, SCRIPT_VERSION, SCRIPT_TIMESTAMP))
    return weechat.WEECHAT_RC_OK
  
  def receive_advertise(data, buffer, tags, prefix, args):
    global WRECON_REMOTE_BOTS_ADVERTISED
    # PROTOCOL: COMMAND TO_BOTID|HASH FROM_BOTID HASH [DATA]
    v_remote_bot_id   = args[1]
    v_bot_hash_cmd    = args[2]
    v_remote_bot_name = f_get_name(1, args)
    v_remote_bot_data = '%s|%s' % (v_remote_bot_name, f_get_nick_info(tags, prefix))
    WRECON_REMOTE_BOTS_ADVERTISED[v_remote_bot_id] = v_remote_bot_data
    f_message_simple(data, buffer, 'REMOTE BOT REGISTERED : %s (%s)' % (v_remote_bot_id, v_remote_bot_name))
    return weechat.WEECHAT_RC_OK
  
  def receive_advertise_error(data, buffer, tags, prefix, args):
    global WRECON_REMOTE_BOTS_ADVERTISED
    if args[1] in WRECON_REMOTE_BOTS_ADVERTISED:
      del WRECON_REMOTE_BOTS_ADVERTISED[args[1]]
    f_message_simple(data, buffer, 'REMOTE BOT UNREGISTERED : %s' % (args[1]))
    return weechat.WEECHAT_RC_OK
  
  def reply_advertise_additionally(data, buffer, tags, prefix, args):
    global BUFFER_CMD_ADA_REP, WRECON_BOT_NAME, SCRIPT_VERSION, SCRIPT_TIMESTAMP
    f_message_simple(data, buffer, 'RECEIVED ADDITIONAL ADVERTISE from %s' % (args[1]))
    weechat.command(buffer, '%s %s %s %s %s [v%s %s]' % (BUFFER_CMD_ADA_REP, args[1], args[0], args[2], WRECON_BOT_NAME, SCRIPT_VERSION, SCRIPT_TIMESTAMP))
    return weechat.WEECHAT_RC_OK
  
  def receive_advertise_additionally(data, buffer, tags, prefix, args):
    global ADDITIONAL_ADVERTISE
    additional_key = '%s%s' % (args[1], args[2])
    if not additional_key in ADDITIONAL_ADVERTISE:
      receive_advertise_error(data, buffer, tags, prefix, args)
    else:
      receive_advertise(data, buffer, tags, prefix, args)
      xcmd    = ADDITIONAL_ADVERTISE[additional_key][0]
      xdata   = ADDITIONAL_ADVERTISE[additional_key][1]
      xbuffer = ADDITIONAL_ADVERTISE[additional_key][2]
      xtags   = ADDITIONAL_ADVERTISE[additional_key][3]
      xprefix = ADDITIONAL_ADVERTISE[additional_key][4]
      xargs   = ADDITIONAL_ADVERTISE[additional_key][5]
      command_validate_remote_bot(xdata, xbuffer, xcmd, xtags, xprefix, xargs)
    return weechat.WEECHAT_RC_OK
  
  SCRIPT_BUFFER_CALL[BUFFER_CMD_ADV_EXE] = reply_advertise
  SCRIPT_BUFFER_CALL[BUFFER_CMD_ADV_REP] = receive_advertise
  SCRIPT_BUFFER_CALL[BUFFER_CMD_ADV_ERR] = receive_advertise_error
  SCRIPT_BUFFER_CALL[BUFFER_CMD_ADA_EXE] = reply_advertise_additionally
  SCRIPT_BUFFER_CALL[BUFFER_CMD_ADA_REP] = receive_advertise_additionally

  #
  ##### END COMMAND ADVERTISE


  #####
  #
  # COMMAND DELETE REMOTE BOT FROM control
  
  def command_del_control_bot(data, buffer, NULL1, NULL2, cmd_hash, args):
    global WRECON_REMOTE_BOTS_CONTROL
    v_err       = False
    v_err_topic = 'DELETE ERROR'
    if args:
      if len(args) == 1:
        if args[0] in WRECON_REMOTE_BOTS_CONTROL:
          del WRECON_REMOTE_BOTS_CONTROL[args[0]]
          weechat.command(buffer, '/secure set WRECON_REMOTE_BOTS_CONTROL %s' % (WRECON_REMOTE_BOTS_CONTROL))
          f_message(data, buffer, 'DELETE', ['BOT SUCCESSFULLY DELETED'])
        else:
          f_message(data, buffer, v_err_topic, ['UNKNOWN BOT ID'])
      else:
        v_err = True
    else:
      v_err = True
    if v_err == True:
      if args:
        f_message(data, buffer, v_err_topic, ['INCORRECT NUMBER OF ARGUMENTS > 1 expected.'])
      else:
        f_message(data, buffer, v_err_topic, ['MISSING ARGUMENT > 1 expected.'])
    return weechat.WEECHAT_RC_OK
  
  SCRIPT_ARGS                   = SCRIPT_ARGS + ' | [DEL[ETE] <botid>]'
  SCRIPT_ARGS_DESCRIPTION       = SCRIPT_ARGS_DESCRIPTION + '''
  %(bold)s%(italic)s--- DEL <botid>%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
  Delete remote bot from your control.
    /wrecon DEL %s
  ''' % (f_random_generator(16))
  SCRIPT_COMPLETION             = SCRIPT_COMPLETION + ' || DEL || DELETE'
  SCRIPT_COMMAND_CALL['del']    = command_del_control_bot
  SCRIPT_COMMAND_CALL['delete'] = command_del_control_bot
  
  #
  ##### END COMMAND DELETE REMOTE BOT FROM control


  #####
  #
  # COMMAND GRANT
  
  def command_grant_bot(data, buffer, NULL1, NULL2, cmd_hash, args):
    global WRECON_REMOTE_BOTS_GRANTED
    v_err       = False
    v_err_topic = 'GRANT ERROR'
    if len(args) >= 1:
      new_remote_bot_id  = args[0]
      if len(args) == 1:
        WRECON_REMOTE_BOTS_GRANTED[new_remote_bot_id] = ''
      else:
        args.pop(0)
        WRECON_REMOTE_BOTS_GRANTED[new_remote_bot_id] = ' '.join(map(str, args))
      weechat.command(buffer, '/secure set WRECON_REMOTE_BOTS_GRANTED %s' % (WRECON_REMOTE_BOTS_GRANTED))
      f_message_simple(data, buffer, 'BOT SUCCESSFULLY GRANTED')
    else:
      v_err = True
    if v_err == True:
      f_message(data, buffer, v_err_topic, ['MISSING ARGUMENTS > 1 minimum expected.'])
    return weechat.WEECHAT_RC_OK
  
  SCRIPT_ARGS                  = SCRIPT_ARGS + ' | [G[RANT] <botid> [note]]'
  SCRIPT_ARGS_DESCRIPTION      = SCRIPT_ARGS_DESCRIPTION + '''
  %(bold)s%(italic)s--- G[RANT] <botid> [note]%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
  Grant access to your system for remote bot by botid. For update of your note of bot you can do execute GRANT command again.
  Opposite of command GRANT is command REVOKE.
    /wrecon GRANT %s
    /wrecon G %s
    /wrecon G %s %s
    ''' % (f_random_generator(16), f_random_generator(16), f_random_generator(16), random.choice(WRECON_DEFAULT_BOTNAMES))
  SCRIPT_COMPLETION            = SCRIPT_COMPLETION + ' || G || GRANT'
  SCRIPT_COMMAND_CALL['grant'] = command_grant_bot
  SCRIPT_COMMAND_CALL['g']     = command_grant_bot

  
  #
  ##### END COMMAND GRANT

  #####
  #
  # COMMAND HELP
  
  global SCRIPT_SELF_PATH, HELP_TAG_START, HELP_TAG_END
  SCRIPT_SELF_PATH = os.path.realpath(__file__)
  HELP_TAG_START   = 'Brief' + 'Help' + '>>>'
  HELP_TAG_END     = '<<<' + 'Brief' + 'Help'
  
  '''BriefHelp>>>

For detailed help type /help wrecon

ADD        ADD botid botkey [a note]
ADVERTISE  A[DVERTISE]
DEL        DEL botid
GRANT      G[RANT] botid [a note]
HELP       H[ELP]
LIST       A[DDED]|G[RANTED]
ME         M[E]
REGISTER   REG[ISTER] channelkey channelencryptkey
RENAME     REN[AME] M[YBOT]|botid a new name
REVOKE     REV[OKE] botid
SSH        S[SH] botid
UNREGISTER UN[REGISTER]
UPDATE     UP[DATE] [botid]

<<<BriefHelp
  '''
  
  def command_help(data, buffer, NULL1, NULL2, cmd_hash, args):
    global SCRIPT_SELF_PATH, HELP_TAG_START, HELP_TAG_END
    SHOW_HELP   = False
    SCRIPT_FILE = open(SCRIPT_SELF_PATH, 'r')
    OUT_MSG     = []
    OUT_TITLE   = 'SHORT HELP %s %s [%s]' % (SCRIPT_NAME, SCRIPT_VERSION, SCRIPT_TIMESTAMP)
    for SHOW_LINE in SCRIPT_FILE:
      SHOW_ME = SHOW_LINE.rstrip('\n')
      if HELP_TAG_END in SHOW_ME:
        SHOW_HELP = False
      if SHOW_HELP == True:
          OUT_MSG.append(SHOW_ME)
      if HELP_TAG_START in SHOW_ME:
        SHOW_HELP = True
    SCRIPT_FILE.close()
    f_message(data, buffer, OUT_TITLE, OUT_MSG)
    return weechat.WEECHAT_RC_OK
    
  SCRIPT_ARGS                  = SCRIPT_ARGS + ' | [H[ELP]]'
  SCRIPT_ARGS_DESCRIPTION      = SCRIPT_ARGS_DESCRIPTION + '''
  %(bold)s%(italic)s--- H[ELP]%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
  Command will show short help of commands (overview). For detailed help use /help wrecon.
    /wrecon h
    /wrecon help
    '''
  SCRIPT_COMPLETION           = SCRIPT_COMPLETION + ' || H || HELP'
  SCRIPT_COMMAND_CALL['h']    = command_help
  SCRIPT_COMMAND_CALL['help'] = command_help
  
  #
  ##### END COMMAND HELP

  #####
  #
  # COMMAND LIST
  
  def command_list_bot(data, buffer, NULL1, NULL2, cmd_hash, args):
    global WRECON_REMOTE_BOTS_CONTROL, WRECON_REMOTE_BOTS_GRANTED, WRECON_REMOTE_BOTS_ADVERTISED
    v_err       = False
    v_err_topic = 'LIST ERROR'
    v_topic     = 'LIST INFO'
    if len(args) == 1:
      v_param = args[0].lower()
      if v_param in ['a', 'added', 'g', 'granted']:
        out_message = []
        if v_param in ['a', 'added']:
          if WRECON_REMOTE_BOTS_CONTROL:
            for reg_bot in WRECON_REMOTE_BOTS_CONTROL:
              if len(WRECON_REMOTE_BOTS_CONTROL[reg_bot]) == 1:
                out_msg = reg_bot
              else:
                out_msg = '%s - %s' % (reg_bot, WRECON_REMOTE_BOTS_CONTROL[reg_bot][1])
              if reg_bot in WRECON_REMOTE_BOTS_ADVERTISED:
                out_msg = out_msg + ' (%s)' % WRECON_REMOTE_BOTS_ADVERTISED[reg_bot].split('|')[0]
              out_message.append(out_msg)
            f_message(data, buffer, '%s ADDED BOTS' % (v_topic), out_message)
          else:
            f_message(data, buffer, '%s ADDED BOTS' % (v_topic), ['No registered remote bots'])
        else:
          if WRECON_REMOTE_BOTS_GRANTED:
            for reg_bot in WRECON_REMOTE_BOTS_GRANTED:
              if len(WRECON_REMOTE_BOTS_GRANTED[reg_bot]) == 0:
                out_msg = reg_bot
              else:
                out_msg = '%s - %s' % (reg_bot, WRECON_REMOTE_BOTS_GRANTED[reg_bot])
              if reg_bot in WRECON_REMOTE_BOTS_ADVERTISED:
                out_msg = out_msg + ' (%s)' % (WRECON_REMOTE_BOTS_ADVERTISED[reg_bot]).split('|')[0]
              out_message.append(out_msg)
            f_message(data, buffer, '%s GRANTED BOTS' % (v_topic), out_message)
          else:
            f_message(data, buffer, '%s GRANTED BOTS' % (v_topic), ['No registered granted bots'])
      else:
        f_message(data, buffer, v_err_topic, ['UNKNOWN PARAMETER'])
    else:
      v_err = True
    if v_err == True:
      if args:
        f_message(data, buffer, v_err_topic, ['TOO MANY PARAMETERS > 1 expected.'])
      else:
        f_message(data, buffer, v_err_topic, ['MISSING PARAMETER > 1 expected.'])
    return weechat.WEECHAT_RC_OK
    
  SCRIPT_ARGS                   = SCRIPT_ARGS + ' | [L[IST] <A[DDED]>|<G[RANTED]>]'
  SCRIPT_ARGS_DESCRIPTION       = SCRIPT_ARGS_DESCRIPTION + '''
  %(bold)s%(italic)s--- L[IST] <A[DDED]>|<G[RANTED]>%(nitalic)s%(nbold)s
  List of ADDED bots you can control, or GRANTED bots which can control your system.
    /wrecon LIST ADDED
    /wrecon L A
    /wrecon LIST G
    /wrecon L GRANTED
  ''' % COLOR_TEXT
  SCRIPT_COMPLETION           = SCRIPT_COMPLETION + ' || L || LIST'
  SCRIPT_COMMAND_CALL['l']    = command_list_bot
  SCRIPT_COMMAND_CALL['list'] = command_list_bot
  
  #
  ##### END COMMAND LIST


  #####
  #
  # COMMANDS ME
  
  def command_me(data, buffer, NULL1, NULL2, cmd_hash, args):
    global WRECON_SERVER, WRECON_CHANNEL, WRECON_CHANNEL_KEY, WRECON_CHANNEL_ENCRYPTION_KEY, WRECON_BOT_NAME, WRECON_BOT_ID, WRECON_BOT_KEY, SCRIPT_VERSION, SCRIPT_TIMESTAMP
    info_message     = ['Bot Name  : %s' % (WRECON_BOT_NAME)]
    info_message.append('Bot ID    : %s' % (WRECON_BOT_ID))
    info_message.append('Bot KEY   : %s' % (WRECON_BOT_KEY))
    info_message.append('VERSION   : %s' % (SCRIPT_VERSION))
    info_message.append('TIMESTAMP : %s' % (SCRIPT_TIMESTAMP))
    if WRECON_CHANNEL and WRECON_SERVER:
      info_message.append('--- REGISTERED SERVER and CHANNEL ---')
      info_message.append('SERVER                 : %s' % (WRECON_SERVER))
      info_message.append('CHANNEL                : %s' % (WRECON_CHANNEL))
      info_message.append('CHANNEL KEY            : %s' % (WRECON_CHANNEL_KEY))
      info_message.append('CHANNEL ENCRYPTION KEY : %s' % (WRECON_CHANNEL_ENCRYPTION_KEY))
    f_message(data, buffer, 'INFO', info_message)
    return weechat.WEECHAT_RC_OK
  
  SCRIPT_ARGS               = SCRIPT_ARGS + '[M[E]]'
  SCRIPT_ARGS_DESCRIPTION   = SCRIPT_ARGS_DESCRIPTION + '''
  %(bold)s%(italic)s--- M[E]%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
  Show information about your bot Name, ID and KEY. In case you have registered Server and Channel, these informations will be shown as well.
  Information is displayed only to your buffer and not send to the Channel.
    /wrecon M
    /wrecon ME
  '''
  SCRIPT_COMPLETION         = SCRIPT_COMPLETION + 'M || ME'
  SCRIPT_COMMAND_CALL['m']  = command_me
  SCRIPT_COMMAND_CALL['me'] = command_me
  
  #
  ##### END COMMAND ME


  #####
  #
  # COMMAND REGISTER CHANNEL
  
  def command_register_channel(data, buffer, NULL1, NULL2, cmd_hash, args):
    v_err = False
    if len(args) == 2:
      global WRECON_CHANNEL, WRECON_SERVER, WRECON_CHANNEL_KEY, WRECON_CHANNEL_ENCRYPTION_KEY, WRECON_BUFFER_CHANNEL
      if WRECON_SERVER and WRECON_CHANNEL:
        v_err = True
      else:
        WRECON_CHANNEL_KEY            = args[0]
        WRECON_CHANNEL_ENCRYPTION_KEY = args[1]
        WRECON_SERVER                 = weechat.buffer_get_string(buffer, 'localvar_server')
        WRECON_CHANNEL                = weechat.buffer_get_string(buffer, 'localvar_channel')
        WRECON_BUFFER_CHANNEL         = buffer
        v_message_out     = ['SERVER                 : %s' % (WRECON_SERVER)]
        v_message_out.append('CHANNEL                : %s' % (WRECON_CHANNEL))
        v_message_out.append('CHANNEL KEY            : %s' % (WRECON_CHANNEL_KEY))
        v_message_out.append('CHANNEL ENCRYPTION KEY : %s' % (WRECON_CHANNEL_ENCRYPTION_KEY))
        f_message(data, buffer, 'REGISTER INFO', v_message_out)
        weechat.command(buffer, '/secure set wrecon_server %s' % (WRECON_SERVER))
        weechat.command(buffer, '/secure set wrecon_channel %s' % (WRECON_CHANNEL))
        weechat.command(buffer, '/secure set wrecon_channel_key %s' % (WRECON_CHANNEL_KEY))
        f_change_modeop(data, buffer, WRECON_SERVER, WRECON_CHANNEL)
        weechat.command(buffer, '/secure set wrecon_channel_encryption_key %s' % (WRECON_CHANNEL_ENCRYPTION_KEY))
        weechat.command(buffer, '/ircrypt set-key -server %s %s %s' % (WRECON_SERVER, WRECON_CHANNEL, WRECON_CHANNEL_ENCRYPTION_KEY))
        weechat.command(buffer, '/ircrypt set-cipher -server %s %s aes256' % (WRECON_SERVER, WRECON_CHANNEL))
        
        f_buffer_hook()
        
        save_options = False
        wrecon_server_autoconnect   = weechat.string_eval_expression("${irc.server.%s.autoconnect}" % (WRECON_SERVER), {}, {}, {})
        wrecon_server_autoreconnect = weechat.string_eval_expression("${irc.server.%s.autoreconnect}" % (WRECON_SERVER), {}, {}, {})
        wrecon_channel_autorejoin   = weechat.string_eval_expression("${irc.server.%s.autorejoin}" % (WRECON_SERVER), {}, {}, {})
        
        if wrecon_server_autoconnect != 'on':
          weechat.command(buffer, '/set irc.server.%s.autoconnect on' % (WRECON_SERVER))
          save_options = True
        
        if wrecon_server_autoreconnect != 'on':
          weechat.command(buffer, '/set irc.server.%s.autoreconnect on' % (WRECON_SERVER))
          save_options = True
        
        if wrecon_channel_autorejoin != 'on':
          weechat.command(buffer, '/set irc.server.%s.autorejoin on' % (WRECON_SERVER))
          save_options = True
        
        setup_add = f_setup_autojoin_add(buffer, WRECON_SERVER, WRECON_CHANNEL)
        if setup_add == True:
          save_options = True
        
        if save_options == True:
          weechat.command(buffer, '/save')
    else:
      v_err = True
    if v_err == True:
      if WRECON_SERVER and WRECON_CHANNEL:
        f_message(data, buffer, 'REGISTER ERROR', ['ALREADY REGISTERED > First UNREGISTER, then REGISTER again.'])
      else:
        f_message(data, buffer, 'REGISTER ERROR', ['MISSING PARAMETERS > 2 expected. See help.'])
    return weechat.WEECHAT_RC_OK
  
  SCRIPT_ARGS                     = SCRIPT_ARGS + ' | [REG[ISTER] <CHANNEL_KEY> <ENCRYPT_KEY>]'
  SCRIPT_ARGS_DESCRIPTION         = SCRIPT_ARGS_DESCRIPTION + '''
  %(bold)s%(italic)s--- REG[ISTER] <channel_key> <encrypt_key>%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
  Register current channel for controling remote bot's. You have to be actively connected to server and joined in channel you need register.
  Opposite of command REGISTER is command UNREGISTER.
    /wrecon REG %s %s
    /wrecon REGISTER %s %s
  ''' % (f_random_generator(8), f_random_generator(16), f_random_generator(8), f_random_generator(16))
  SCRIPT_COMPLETION               = SCRIPT_COMPLETION + ' || REG || REGISTER'
  SCRIPT_COMMAND_CALL['reg']      = command_register_channel
  SCRIPT_COMMAND_CALL['register'] = command_register_channel
  
  #
  ##### END COMMAND REGISTER CHANNEL

  
  #####
  #
  # COMMAND RENAME MYBOT or REMOTE BOT
  
  global BUFFER_CMD_REN_EXE, BUFFER_CMD_REN_REP, uniq_hash_cmd_rename
  BUFFER_CMD_REN_EXE   = '%sE-REN'   % (COMMAND_IN_BUFFER)
  BUFFER_CMD_REN_REP   = '%sREN-R'   % (COMMAND_IN_BUFFER)
  uniq_hash_cmd_rename = ''
  
  def f_save_new_name(data, buffer, newname):
    global WRECON_BOT_NAME, WRECON_SERVER, WRECON_CHANNEL, WRECON_BOT_ID, REMOTE_ADVERTISED
    REMOTE_ADVERTISED = False
    weechat.command(buffer,'/secure set WRECON_BOT_NAME %s' % (newname))
    WRECON_BOT_NAME = newname
    info_message = ['Your bot Name has been changed to \'%s\'' % (newname)]
    f_change_buffer_title()
    f_message(data, buffer, 'RENAME INFO', info_message)
    command_advertise(data, buffer, '', '')
    return weechat.WEECHAT_RC_OK
  

  def command_rename(data, buffer, NULL1, NULL2, cmd_hash, args):
    v_err       = False
    v_err_topic = 'RENAME ERROR'
    v_topic     = 'RENAME INFO'
    if args:
      if len(args) >= 2:
        global wrecon_bot_newname, WRECON_BUFFER_CHANNEL, uniq_hash
        if args[0].lower() == 'm' or args[0].lower() == 'mybot':
          f_save_new_name(data, WRECON_BUFFER_CHANNEL, f_get_name(0, args))
        else:
          command_rename_remote(data, buffer, args)
      else:
        v_err=True
    else:
      v_err=True
    if v_err == True:
      err_message     = ['MISSING PARAMETERS > 2 minimum expected, see following examples']
      err_message.append('/wrecon ren[ame] m[ybot] NewName')
      err_message.append('/wrecon ren[ame] botid NewName Surname')
      f_message(data, buffer, v_err_topic, err_message)
    return weechat.WEECHAT_RC_OK
    
  SCRIPT_ARGS                   = SCRIPT_ARGS + ' | [REN[AME] <M[YBOT]|botid> <newname>]'
  SCRIPT_ARGS_DESCRIPTION       = SCRIPT_ARGS_DESCRIPTION + '''
  %(bold)s%(italic)s--- REN[AME] <M[YBOT]|botid> <newname>%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
  Rename bot. For local bot use option M or MYBOT, for remote botid.
    /wrecon RENAME MYBOT %s
    /wrecon RENAME %s %s
    /wrecon REN M %s
    ''' % (random.choice(WRECON_DEFAULT_BOTNAMES), f_random_generator(16), random.choice(WRECON_DEFAULT_BOTNAMES), random.choice(WRECON_DEFAULT_BOTNAMES))
  SCRIPT_COMPLETION             = SCRIPT_COMPLETION + ' || REN || RENAME'
  SCRIPT_COMMAND_CALL['ren']    = command_rename
  SCRIPT_COMMAND_CALL['rename'] = command_rename
  
  def command_rename_remote(data, buffer, args):
    global WRECON_BOT_ID
    # Check if bot id belong to own bot
    if args[0] == WRECON_BOT_ID:
      f_save_new_name(data, buffer, f_get_name(0, args))
    else:
      # Check if bot is registered (added in bots you control)
      global WRECON_REMOTE_BOTS_CONTROL
      if args[0] in WRECON_REMOTE_BOTS_CONTROL:
        global BUFFER_CMD_REN_EXE, uniq_hash_cmd_rename
        uniq_hash_cmd_rename = f_command_counter()
        # PROTOCOL: COMMAND TO_BOT_ID FROM_BOT_ID HASH [DATA]
        weechat.command(buffer, '%s %s %s %s %s' % (BUFFER_CMD_REN_EXE, args[0], WRECON_BOT_ID, uniq_hash_cmd_rename, f_get_name(0, args)))
      else:
        f_message(data, buffer, 'RENAME ERROR', ['REMOTE BOT %s IS NOT ADDED/REGISTERED' % (args[0])])
    return weechat.WEECHAT_RC_OK
  
  global remote_cmd_rename_hash, remote_cmd_rename_botid
  remote_cmd_rename_hash  = ''
  remote_cmd_rename_botid = ''
  
  def f_get_name(x, args):
    args.pop(0)
    if x == 1:
      args.pop(0)
      args.pop(0)
    return ' '.join([str(elem) for elem in args])
  
  def f_rename_validated(data, buffer, tags, prefix, args):
    f_save_new_name(data, buffer, f_get_name(1, args))
    return weechat.WEECHAT_RC_OK
    
  def receive_rename(data, buffer, tags, prefix, args):
    # ~ f_message_simple(data, buffer, 'RENAME CALLED : %s' % (args))
    # Check the RENAME command is for my BOT
    command_validate_remote_bot(data, buffer, f_rename_validated, tags, prefix, args)
    return weechat.WEECHAT_RC_OK

  SCRIPT_BUFFER_CALL[BUFFER_CMD_REN_EXE]  = receive_rename
  
  #
  ##### END COMMAND RENAME MYBOT or REMOTE BOT
  
  #####
  #
  # COMMAND REVOKE
  
  def command_revoke(data, buffer, NULL1, NULL2, cmd_hash, args):
    global WRECON_REMOTE_BOTS_GRANTED
    v_err       = False
    v_err_topic = 'REVOKE ERROR'
    v_topic     = 'REVOKE INFO'
    if len(args) == 1:
      if args[0] in WRECON_REMOTE_BOTS_GRANTED:
        del WRECON_REMOTE_BOTS_GRANTED[args[0]]
        weechat.command(buffer, '/secure set WRECON_REMOTE_BOTS_GRANTED %s' % (WRECON_REMOTE_BOTS_GRANTED))
        f_message(data, buffer, v_topic, ['BOT SUCCESFULLY REVOKED'])
      else:
        f_message(data, buffer, v_err_topic, ['UNKNOWN BOT ID'])
    else:
      v_err = True
    if v_err == True:
      if args:
        f_message(data, buffer, v_err_topic, ['TOO MANY PARAMETERS > 1 expected.'])
      else:
        f_message(data, buffer, v_err_topic, ['MISSING PARAMETER > 1 expected.'])
    return weechat.WEECHAT_RC_OK
  
  SCRIPT_ARGS                   = SCRIPT_ARGS + ' | [REV[OKE] <botid>]'
  SCRIPT_ARGS_DESCRIPTION       = SCRIPT_ARGS_DESCRIPTION + '''
  %(bold)s%(italic)s--- REV[OKE] <botid>%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
  Revoke granted access to your system of remote bot.
    /wrecon REVOKE %s
    /wrecon REV %s
    ''' % (f_random_generator(16), f_random_generator(16))
  SCRIPT_COMPLETION             = SCRIPT_COMPLETION + ' || REV || REVOKE'
  SCRIPT_COMMAND_CALL['rev']    = command_revoke
  SCRIPT_COMMAND_CALL['revoke'] = command_revoke

  #
  ##### END COMMAND REVOKE
  
  
  #####
  #
  # COMMAND SSH
  
  global BUFFER_CMD_SSH_EXE, BUFFER_CMD_SSH_REP, uniq_hash_cmd_ssh, SSH_GLOBAL_OUTPUT
  BUFFER_CMD_SSH_EXE = '%sE-SSH' % (COMMAND_IN_BUFFER)
  BUFFER_CMD_SSH_REP = '%sSSH-R' % (COMMAND_IN_BUFFER)
  BUFFER_CMD_SSH_REK = '%sSSH-K' % (COMMAND_IN_BUFFER)
  uniq_hash_cmd_ssh = ''
  SSH_GLOBAL_OUTPUT = []
  
  def command_ssh(data, buffer, NULL1, NULL2, cmd_hash, args):
    global WRECON_REMOTE_BOTS_CONTROL
    global WRECON_BOT_ID, BUFFER_CMD_SSH_EXE
    v_err       = False
    v_err_topic = 'SSH ERROR'
    v_topic     = 'SSH INFO'
    # PROTOCOL: COMMAND TO_BOT_ID FROM_BOT_ID HASH [DATA]
    if len(args) == 1:
      global WRECON_REMOTE_BOTS_CONTROL
      # 1. Check we have registered remote bot
      if not args[0] in WRECON_REMOTE_BOTS_CONTROL:
        f_message(data, buffer, v_err_topic, ['REMOTE BOT %s IS NOT ADDED/REGISTERED' % (args[0])])
      else:
        global WRECON_REMOTE_BOTS_ADVERTISED
        # 2. Check remote bot has been advertised
        if not args[0] in WRECON_REMOTE_BOTS_ADVERTISED:
          global ADDITIONAL_ADVERTISE
          additional_key = '%s%s' % (args[0], cmd_hash)
          if not additional_key in ADDITIONAL_ADVERTISE:
            # Request additional advertise of remote bot
            global BUFFER_CMD_ADA_EXE, SCRIPT_VERSION, SCRIPT_TIMESTAMP, SCRIPT_COMMAND_CALL, WRECON_BOT_ID
            # ~ f_message_simple(data, buffer, 'ARGS : %s' % args)
            weechat.command(buffer, '%s %s %s %s [v%s %s]' % (BUFFER_CMD_ADA_EXE, args[0], WRECON_BOT_ID, cmd_hash, SCRIPT_VERSION, SCRIPT_TIMESTAMP))
            ADDITIONAL_ADVERTISE[additional_key] = [SCRIPT_COMMAND_CALL['s'], data, buffer, '', '', args]
          else:
            # In case remote bot has been additionally asked for advertisement and was not advertised, then it is error
            f_message(data, buffer, v_err_topic, ['REMOTE BOT %s WAS NOT ADVERTISED' % (args[0])])
            del ADDITIONAL_ADVERTISE[additional_key]
        else:
          weechat.command(buffer, '%s %s %s %s' % (BUFFER_CMD_SSH_EXE, args[0], WRECON_BOT_ID, cmd_hash))
    else:
      err_message     = ['INCORRECT NUMBER OF PARAMETERS > 1 expected, see following examples']
      err_message.append('/wrecon ssh botid')
      f_message(data, buffer, v_err_topic, err_message)
    return weechat.WEECHAT_RC_OK
  
  SCRIPT_ARGS                = SCRIPT_ARGS + ' | [S[SH] <botid>]'
  SCRIPT_ARGS_DESCRIPTION    = SCRIPT_ARGS_DESCRIPTION + '''
  %(bold)s%(italic)s--- SSH <botid>%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
  Start remote SSH for your access on remote bot.
    /wrecon SSH %s
    ''' % (f_random_generator(16))
  SCRIPT_COMPLETION          = SCRIPT_COMPLETION + ' || S || SSH'
  SCRIPT_COMMAND_CALL['s']   = command_ssh
  SCRIPT_COMMAND_CALL['ssh'] = command_ssh
  
  def receive_ssh(data, buffer, tags, prefix, args):
    command_validate_remote_bot(data, buffer, f_ssh_validated, tags, prefix, args)
    return weechat.WEECHAT_RC_OK
  
  global SSH_HOOK_PROCESS, SSH_PROCESS_DATA, ssh_timeout, SSH_OUT, SSH_ERR
  SSH_HOOK_PROCESS = ''
  SSH_PROCESS_DATA = []
  ssh_timeout      = 0
  SSH_OUT          = ''
  SSH_ERR          = ''
  
  # PROCESS SSH (tmate) CALLBACK, sent resutl to remote BOT in encrypted form
  def f_ssh_publish_data_callback(data, command, rc, out, err):
    global SSH_OUT, SSH_ERR
    SSH_OUT += out
    SSH_ERR += err
    if int(rc) >= 0:
      global SSH_HOOK_PROCESS, SSH_PROCESS_DATA, BUFFER_CMD_SSH_REP, WRECON_BOT_KEY, BUFFER_CMD_SSH_REK
      # ~ data   = SSH_PROCESS_DATA[0]
      buffer = SSH_PROCESS_DATA[1]
      # ~ tags   = SSH_PROCESS_DATA[2]
      # ~ prefix = SSH_PROCESS_DATA[3]
      args   = SSH_PROCESS_DATA[4]
      DATA_T = 'DATA'
      if SSH_OUT:
        DATA_T    = 'DATA'
        OUT_LINES = SSH_OUT.rstrip().split('\n')
      if SSH_ERR:
        DATA_T    = 'ERROR'
        OUT_LINES = SSH_ERR.rstrip().split('\n')
      for OUT_LINE in OUT_LINES:
        out_message       = '%s|%s' % (DATA_T, OUT_LINE)
        message_encrypted = f_encrypt_string(out_message, WRECON_BOT_KEY)
        weechat.command(buffer, '%s %s %s %s %s' % (BUFFER_CMD_SSH_REP, args[1], args[0], args[2], message_encrypted))
      #weechat.unhook(SSH_HOOK_PROCESS)
      SSH_HOOK_PROCESS = ''
      weechat.command(buffer, '%s %s %s %s %s' % (BUFFER_CMD_SSH_REK, args[1], args[0], args[2], BUFFER_CMD_SSH_REK))
    return weechat.WEECHAT_RC_OK
  
  # Call SSH (tmate) PROCESS after remote BOT was validated
  def f_ssh_validated(data, buffer, tags, prefix, args):
    global SSH_HOOK_PROCESS
    if SSH_HOOK_PROCESS:
      weechat.command(buffer, '%s : ANOTHER SSH IS RUNNING')
    else:
      global SSH_PROCESS_DATA, ssh_timeout, SSH_OUT, SSH_ERR, SSH_GLOBAL_OUTPUT
      SSH_GLOBAL_OUTPUT = []
      SSH_OUT           = ''
      SSH_ERR           = ''
      SSH_PROCESS_DATA  = [data, buffer, tags, prefix, args]
      v_process_id      = 'wrecon-%s%s' % (args[0], args[2])
      v_process_file    = '/tmp/%s' % (v_process_id)
      v_command         = "unset TMUX && tmate -S %s new-session -d && tmate -S %s wait tmate-ready && tmate -S %s display -p '#{tmate_web_ro}' && tmate -S %s display -p '#{tmate_web}' && tmate -S %s display -p '#{tmate_ssh_ro}' && tmate -S %s display -p '#{tmate_ssh}' && tmate -S %s send-keys q" % (v_process_file, v_process_file, v_process_file, v_process_file, v_process_file, v_process_file, v_process_file)
      f_message_simple(data, buffer, '%s : EXE : %s' % (args[2], v_command))
      v_version         = weechat.info_get("version_number", "") or 0
      if int(v_version) >= 0x00040000:
        SSH_HOOK_PROCESS = weechat.hook_process_hashtable('bash', {'arg1': '-c', 'arg2': v_command}, ssh_timeout * 1000, 'f_ssh_publish_data_callback', v_command)
      else:
        SSH_HOOK_PROCESS = weechat.hook_process("bash -c '%s'" % v_command, ssh_timeout * 1000, 'f_ssh_publish_data_callback', v_command)
    return weechat.WEECHAT_RC_OK
  
  # Receive SSH (tmate) data from remote BOT
  def receive_ssh_reply(data, buffer, tags, prefix, args):
    global WRECON_REMOTE_BOTS_CONTROL, BUFFER_CMD_SSH_REK, SSH_GLOBAL_OUTPUT
    remote_bot_id = args[1]
    if BUFFER_CMD_SSH_REK in args:
      f_message_simple(data, buffer, '')
      v_data  = SSH_GLOBAL_OUTPUT[0].split('|')[0]
      v_topic = 'SSH INFO (%s)' % (v_data)
      OUT_MSG = ['>>> START MESSAGE from %s : %s' % (remote_bot_id, args[2])]
      OUT_MSG.append('')
      for O_M in SSH_GLOBAL_OUTPUT:
        if '|' in O_M:
          O_MESS = O_M.split('|')[1]
        else:
          O_MESS = O_M
        OUT_MSG.append(O_MESS)
      OUT_MSG.append('')
      OUT_MSG.append('END OF MESSAGE from %s : %s <<<' % (remote_bot_id, args[2]))
      OUT_MSG.append('')
      f_message(data, buffer, v_topic, OUT_MSG)
      # ~ f_message_simple(data, buffer, '%s : %s' % (args[2], dec_message))
      SSH_GLOBAL_OUTPUT = []
    else:
      dec_key     = WRECON_REMOTE_BOTS_CONTROL[remote_bot_id][0]
      dec_message = f_decrypt_string(args[3], WRECON_REMOTE_BOTS_CONTROL[args[1]][0])
      SSH_GLOBAL_OUTPUT.append(dec_message)
    return weechat.WEECHAT_RC_OK
  
  SCRIPT_BUFFER_CALL[BUFFER_CMD_SSH_EXE]  = receive_ssh
  SCRIPT_BUFFER_CALL[BUFFER_CMD_SSH_REP]  = receive_ssh_reply
  SCRIPT_BUFFER_CALL[BUFFER_CMD_SSH_REK]  = receive_ssh_reply
  
  #
  ##### END COMMAND SSH

  #####
  #
  # COMMAND UNREGISTER CHANNEL
  
  def command_unregister_channel(data, buffer, NULL1, NULL2, cmd_hash, args):
    global WRECON_CHANNEL, WRECON_SERVER, WRECON_CHANNEL_KEY, WRECON_CHANNEL_ENCRYPTION_KEY
    v_err = False
    if WRECON_CHANNEL and WRECON_SERVER:
      
      save_options = f_setup_autojoin_del(buffer, WRECON_SERVER, WRECON_CHANNEL)
        
      if save_options == True:
        weechat.command(buffer, '/save')
      
      f_buffer_unhook()
      
      weechat.command(buffer, '/secure del wrecon_server')
      weechat.command(buffer, '/secure del wrecon_channel')
      weechat.command(buffer, '/secure del wrecon_channel_key')
      weechat.command(buffer, '/secure del wrecon_channel_encryption_key')
      weechat.command(buffer, '/ircrypt remove-key -server %s %s' % (WRECON_SERVER, WRECON_CHANNEL))
      weechat.command(buffer, '/ircrypt remove-cipher -server %s %s' % (WRECON_SERVER, WRECON_CHANNEL))
      unreg_message     = ['Channel and server unregistered.']
      unreg_message.append('In case you no longer need current channel (%s), remove key from channel by following command:' % (WRECON_CHANNEL))
      unreg_message.append('/mode %s -k' % (WRECON_CHANNEL))
      f_message(data, buffer, 'UNREGISTER', unreg_message)
      WRECON_CHANNEL                = ''
      WRECON_SERVER                 = ''
      WRECON_CHANNEL_ENCRYPTION_KEY = ''
      WRECON_CHANNEL_KEY            = ''
    else:
      v_err = True
    if v_err == True:
      f_message(data, buffer, 'UNREGISTER ERROR', ['No server and channel is registered.'])
    return weechat.WEECHAT_RC_OK
  
  SCRIPT_ARGS                       = SCRIPT_ARGS + ' | [UN[REGISTER]]'
  SCRIPT_ARGS_DESCRIPTION           = SCRIPT_ARGS_DESCRIPTION + '''
  %(bold)s%(italic)s--- UN[REGIISTER]%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
  Unregister channel of controling remote bot's.
      /wrecon UN
      /wrecon UNREGISTER
  '''
  SCRIPT_COMPLETION                 = SCRIPT_COMPLETION + ' || UNREG || UNREGISTER'
  SCRIPT_COMMAND_CALL['un']         = command_unregister_channel
  SCRIPT_COMMAND_CALL['unregister'] = command_unregister_channel
  
  #
  ##### END COMMAND UNREGISTER CHANNEL
  
  #####
  #
  # COMMAND UPDATE
  
  global BUFFER_CMD_UPD_EXE
  BUFFER_CMD_UPD_EXE = '%sE-UPD' % (COMMAND_IN_BUFFER)
  
  def command_update(data, buffer, xtags, xprefix, cmd_hash, args):
    # Check we want update itself (no arguments are expected)
    v_err       = False
    v_err_topic = 'UPDATE ERROR'
    v_topic     = 'UPDATE INFO'
    if not args:
      f_check_and_update(data, buffer)
    else:
    # In case argument was provided, it consider it is remote BOTID
      if len(args) != 1:
        err_msg     = ['MORE ARGUMENTS > 1 or none expected.']
        err_msg.append('/wrecon update [botid]')
        f_message(data, buffer, v_err_topic, err_msg)
      else:
        global WRECON_BOT_ID
        # Check BOTID belong to itself BOTID
        if args[0] == WRECON_BOT_ID:
          f_check_and_update(data, buffer)
        else:
          # Check we have registered remote bot
          global WRECON_REMOTE_BOTS_CONTROL
          if not args[0] in WRECON_REMOTE_BOTS_CONTROL:
            f_message(data, buffer, v_err_topic, ['REMOTE BOT %s IS NOT ADDED/REGISTERED' % (args[0])])
          else:
            # Check remote bot has been advertised
            global WRECON_REMOTE_BOTS_ADVERTISED
            if not args[0] in WRECON_REMOTE_BOTS_ADVERTISED:
              global ADDITIONAL_ADVERTISE
              additional_key = '%s%s' % (args[0], cmd_hash)
              if not additional_key in ADDITIONAL_ADVERTISE:
                # Request additional advertise of remote bot
                global BUFFER_CMD_ADA_EXE, SCRIPT_VERSION, SCRIPT_TIMESTAMP, SCRIPT_COMMAND_CALL
                xargs = args
                xargs.append(WRECON_BOT_ID)
                xargs.append(cmd_hash)
                ADDITIONAL_ADVERTISE[additional_key] = [SCRIPT_COMMAND_CALL['up'], data, buffer, '', '', cmd_hash, xargs]
                weechat.command(buffer, '%s %s %s %s [v%s %s]' % (BUFFER_CMD_ADA_EXE, args[0], WRECON_BOT_ID, cmd_hash, SCRIPT_VERSION, SCRIPT_TIMESTAMP))
              else:
                # In case remote bot has been additionally asked for advertisement and was not  advertised, then it is error
                f_message(data, buffer, v_error_topic, ['REMOTE BOT %s WAS NOT ADVERTISED' % (args[0])])
                del ADDITIONAL_ADVERTISE[additional_key]
            else:
              global BUFFER_CMD_UPD_EXE
              weechat.command(buffer, '%s %s %s %s' % (BUFFER_CMD_UPD_EXE, args[0], WRECON_BOT_ID, cmd_hash))

    return weechat.WEECHAT_RC_OK
  
  SCRIPT_ARGS                       = SCRIPT_ARGS + ' | [UP[DATE] [botid]]'
  SCRIPT_ARGS_DESCRIPTION           = SCRIPT_ARGS_DESCRIPTION + '''
  %(bold)s%(italic)s--- UP[DATE] [botid]%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
  Update script from github. This will check new released version, and in case newest version is found, it will trigger update.
  You can also update remote BOT if you are GRANTED to do. With no argument it will trigger update of local BOT, else update for remote BOT will be called.
      /wrecon UP
      /wrecon UPDATE %s
  ''' % (f_random_generator(16))
  SCRIPT_COMPLETION             = SCRIPT_COMPLETION + ' || UP || UPDATE'
  SCRIPT_COMMAND_CALL['up']     = command_update
  SCRIPT_COMMAND_CALL['update'] = command_update
  
  def receive_update(data, buffer, tags, prefix, args):
    command_validate_remote_bot(data, buffer, f_update_validated, tags, prefix, args)
    return weechat.WEECHAT_RC_OK
  
  # Call UPDATE PROCESS after remote BOT was validated
  def f_update_validated(data, buffer, tags, prefix, args):
    f_check_and_update(data, buffer)
    return weechat.WEECHAT_RC_OK
  
  SCRIPT_BUFFER_CALL[BUFFER_CMD_UPD_EXE] = receive_update

  #
  ##### END COMMAND UPDATE
  
  #####
  #
  # COMMAND VALIDATION (INTERNAL)
  
  global BUFFER_CMD_VAL_EXE, BUFFER_CMD_VAL_REP, BUFFER_CMD_VAL_ERR, BUFFER_CMD_VAL_FUNCTION, ADDITIONAL_ADVERTISE
  BUFFER_CMD_VAL_EXE = '%sE-VAL' % (COMMAND_IN_BUFFER)
  BUFFER_CMD_VAL_REP = '%sVAL-R' % (COMMAND_IN_BUFFER)
  BUFFER_CMD_VAL_ERR = '%sVAL-E' % (COMMAND_IN_BUFFER)
  BUFFER_CMD_VAL_REA = '%sVAL-A' % (COMMAND_IN_BUFFER)
  BUFFER_CMD_VAL_FUNCTION = {}
  ADDITIONAL_ADVERTISE = {}
  
  # Command is called from received remote command (from remote bot)
  def command_validate_remote_bot(data, buffer, call_requested_function, tags, prefix, args):
    global WRECON_BOT_ID
    if args[1] == WRECON_BOT_ID:
      call_requested_function(data, buffer, tags, prefix, args)
    else:
      # ~ global WRECON_REMOTE_BOTS_ADVERTISED, WRECON_REMOTE_BOTS_GRANTED, WRECON_REMOTE_BOTS_VERIFIED
      # args:
      # 0 - TO BOT ID
      # 1 - FROM BOT ID
      # 2 - HASH
      # 3 - [DATA]
      # 
      # 1. check remote bot is granted
      global WRECON_REMOTE_BOTS_GRANTED
      if not args[1] in WRECON_REMOTE_BOTS_GRANTED:
        reply_validation_error(data, buffer, 'ACCESS IS NOT GRANTED', args)
      else:
        # 2. check remote bot was advertised
        global WRECON_REMOTE_BOTS_ADVERTISED, ADDITIONAL_ADVERTISE
        if not args[1] in WRECON_REMOTE_BOTS_ADVERTISED:
          global ADDITIONAL_ADVERTISE
          additional_key = '%s%s' % (args[1], args[2])
          if not additional_key in ADDITIONAL_ADVERTISE:
            # Initiate additional advertise of remote bot
            global BUFFER_CMD_ADA_EXE, SCRIPT_VERSION, SCRIPT_TIMESTAMP
            ADDITIONAL_ADVERTISE[additional_key] = [call_requested_function, data, buffer, tags, prefix, args]
            weechat.command(buffer, '%s %s %s %s [v%s %s]' % (BUFFER_CMD_ADA_EXE, args[1], args[0], args[2], SCRIPT_VERSION, SCRIPT_TIMESTAMP))
          else:
            # In case remote bot has been additionally asked for advertise and was not advertised, then it is error (script on remote site stopped or stuck)
            reply_validation_error(data, buffer, 'PROTOCOL VIOLATION - REMOTE BOT WAS NOT ADVERTISED', args)
            del ADDITIONAL_ADVERTISE[additional_key]
        else:
          # TODO
          # - add new feature for GRANTed BOT (request additional data for first time)
          # - this new feature will be incompatible with older version
          
          # 3. check remote bot was verified
          global WRECON_REMOTE_BOTS_VERIFIED, BUFFER_CMD_VAL_FUNCTION
          v_validated = False
          v_command_key = '%s%s' % (args[1], args[2])
          if args[1] in WRECON_REMOTE_BOTS_VERIFIED:
            # 4. execute function when bot was properly validated
            if WRECON_REMOTE_BOTS_VERIFIED[args[1]] == WRECON_REMOTE_BOTS_ADVERTISED[args[1]]:
              global BUFFER_CMD_VAL_REA
              v_validated = True
              weechat.command(buffer, '%s %s %s %s EXECUTION ACCEPTED' % (BUFFER_CMD_VAL_REA, args[1], args[0], args[2]))
              if v_command_key in BUFFER_CMD_VAL_FUNCTION:
                del BUFFER_CMD_VAL_FUNCTION[v_command_key]
              call_requested_function(data, buffer, tags, prefix, args)
          if v_validated == False:
            # Ensure validation
            global WRECON_BOT_KEY, BUFFER_CMD_VAL_EXE
            generate_seecret = f_random_generator(31)
            send_secret = f_encrypt_string(generate_seecret, WRECON_BOT_KEY)
            BUFFER_CMD_VAL_FUNCTION[v_command_key] = [generate_seecret, call_requested_function, tags, prefix, args]
            weechat.command(buffer, '%s %s %s %s %s' % (BUFFER_CMD_VAL_EXE, args[1], args[0], args[2], send_secret))
            # ~ weechat.command(buffer, 'Wi will do a validation... %s' % (args))
      
    return weechat.WEECHAT_RC_OK
  
  # ~ BUFFER_CMD_VAL_EXE
  def receive_validation(data, buffer, tags, prefix, args):
    global WRECON_REMOTE_BOTS_CONTROL, BUFFER_CMD_VAL_REP
    decrypt_key      = WRECON_REMOTE_BOTS_CONTROL[args[1]][0]
    decrypt_message  = f_decrypt_string(args[3], decrypt_key)
    count_hash       = f_get_hash(decrypt_message)
    send_secret_hash = f_encrypt_string(count_hash, decrypt_key)
    weechat.command(buffer, '%s %s %s %s %s' % (BUFFER_CMD_VAL_REP, args[1], args[0], args[2], send_secret_hash))
    return weechat.WEECHAT_RC_OK
  
  # ~ BUFFER_CMD_VAL_REA
  def receive_validation_accepted(data, buffer, tags, prefix, args):
    return weechat.WEECHAT_RC_OK
  
  # ~ BUFFER_CMD_VAL_REP
  def reply_validation(data, buffer, tags, prefix, args):
    global BUFFER_CMD_VAL_FUNCTION
    v_command_key = '%s%s' % (args[1], args[2])
    if v_command_key in BUFFER_CMD_VAL_FUNCTION:
      global WRECON_BOT_KEY
      decrypt_hash = f_decrypt_string(args[3], WRECON_BOT_KEY)
      stored_hash  = f_get_hash(BUFFER_CMD_VAL_FUNCTION[v_command_key][0])
      if decrypt_hash == stored_hash:
        f_message_simple(data, buffer, 'VALIDATION SUCCESSFUL')
        global WRECON_REMOTE_BOTS_ADVERTISED, WRECON_REMOTE_BOTS_VERIFIED
        WRECON_REMOTE_BOTS_VERIFIED[args[1]] = WRECON_REMOTE_BOTS_ADVERTISED[args[1]]
        exe_command = BUFFER_CMD_VAL_FUNCTION[v_command_key][1]
        exe_tags    = BUFFER_CMD_VAL_FUNCTION[v_command_key][2]
        exe_prefix  = BUFFER_CMD_VAL_FUNCTION[v_command_key][3]
        exe_args    = BUFFER_CMD_VAL_FUNCTION[v_command_key][4]
        exe_command(data, buffer, exe_tags, exe_prefix, exe_args)
        del BUFFER_CMD_VAL_FUNCTION[v_command_key]
      else:
        f_message_simple(data, buffer, 'VALIDATION FAILED')
        reply_validation_error(data, buffer, 'VALIDATION FAILED', args)
    else:
      reply_validation_error(data, buffer, 'PROTOCOL VIOLATION - INVALID VALIDATION REPLY', args)
    return weechat.WEECHAT_RC_OK
  
  # ~ Called from reply_validation only
  def reply_validation_error(data, buffer, errmessage, args):
    global BUFFER_CMD_VAL_ERR, BUFFER_CMD_VAL_FUNCTION
    v_command_key = '%s%s' % (args[1], args[2])
    if v_command_key in BUFFER_CMD_VAL_FUNCTION:
      del BUFFER_CMD_VAL_FUNCTION[v_command_key]
    weechat.command(buffer, '%s %s %s %s %s' % (BUFFER_CMD_VAL_ERR, args[1], args[0], args[2], errmessage))
    return weechat.WEECHAT_RC_OK
    
  # ~ BUFFER_CMD_VAL_ERR
  def receive_validation_error(data, buffer, tags, prefix, args):
    f_message(data, buffer, 'VALIDATION ERROR', '')
    return weechat.WEECHAT_RC_OK
    
  SCRIPT_BUFFER_CALL[BUFFER_CMD_VAL_EXE] = receive_validation
  SCRIPT_BUFFER_CALL[BUFFER_CMD_VAL_REP] = reply_validation
  SCRIPT_BUFFER_CALL[BUFFER_CMD_VAL_REA] = receive_validation_accepted
  SCRIPT_BUFFER_CALL[BUFFER_CMD_VAL_ERR] = receive_validation_error
  
  #
  ##### END COMMAND VALIDATION (INTERNAL)
  
  #
  #
  ##### END COMMANDS - ALL COMMANDS


  #####
  #
  # UNHOOK AND UNLOAD SCRIPT
  
  def wrecon_unload():
    weechat.unhook_all()
    return weechat.WEECHAT_RC_OK
  
  #
  ##### END UNHOOK AND UNLOAD SCRIPT
  
  
  #####
  #
  # PARSING COMMANDS
  
  def parse_commands(data, buffer, args):
    v_arguments = args.split(None, 1)
    if v_arguments:
      v_command = v_arguments[0].lower()
      v_arguments.pop(0)
      if v_command in SCRIPT_COMMAND_CALL:
        if v_arguments:
          v_datasend = v_arguments[0].split(' ')
        else:
          v_datasend = ''
        cmd_hash = f_command_counter()
        SCRIPT_COMMAND_CALL[v_command](data, buffer, '', '', cmd_hash, v_datasend)
      else:
        f_message(data, buffer, 'ERROR', ['INVALID COMMAND > "%s"' % (v_command)])
    else:
      f_message(data, buffer, 'ERROR', ['MISSING COMMAND'])
    return weechat.WEECHAT_RC_OK
  
  SCRIPT_CALLBACK = 'parse_commands'
  
  # WRC-E bot-id counter COMMAND [arguments]
  # WRC-R bot-id counter COMMAND [DATA]
  
  #
  ##### END PARSING COMMANDS
  
  #####
  #
  # PARSING BUFFER REPLY
  
  def parse_buffer(data, buffer, date, tags, displayed, highlight, prefix, message):
    global SCRIPT_BUFFER_CALL
    v_arguments = message.split()
    v_cmd       = v_arguments[0]
    if v_cmd in SCRIPT_BUFFER_CALL:
      # PROTOCOL: COMMAND TO_BOT_ID FROM_BOT_ID HASH [DATA]
      global BUFFER_CMD_ADV_EXE, WRECON_BOT_ID
      v_arguments.pop(0)
      # Check the command from buffer is for advertisement or it belong to our BOT
      if v_cmd == BUFFER_CMD_ADV_EXE or v_arguments[0] == WRECON_BOT_ID:
        xtags   = tags.split(',')
        SCRIPT_BUFFER_CALL[v_cmd](data, buffer, xtags, prefix, v_arguments)
    else:
      f_message(data, buffer, 'ERROR BUFFER COMMAND', ['Unknown command : %s' % (v_cmd)])
    return weechat.WEECHAT_RC_OK
  
  global SCRIPT_CALLBACK_BUFFER
  SCRIPT_CALLBACK_BUFFER = 'parse_buffer'
  
  #
  ##### END PARSING BUFFER REPLY
  
  #####
  #
  # HOOK AND UNHOOK BUFFER
  
  def f_buffer_hook():
    global SCRIPT_CALLBACK_BUFFER, WRECON_BUFFER_HOOKED, WRECON_HOOK_BUFFER, WRECON_BUFFER_CHANNEL
    WRECON_BUFFER_CHANNEL = f_get_buffer_channel()
    if WRECON_BUFFER_HOOKED == False:
      if WRECON_BUFFER_CHANNEL:
        WRECON_BUFFER_HOOKED = True
        WRECON_HOOK_BUFFER    = weechat.hook_print(WRECON_BUFFER_CHANNEL, '', COMMAND_IN_BUFFER, 1, SCRIPT_CALLBACK_BUFFER, '')
    return weechat.WEECHAT_RC_OK
  
  def f_buffer_unhook():
    global WRECON_BUFFER_HOOKED, WRECON_HOOK_BUFFER
    if WRECON_BUFFER_HOOKED == True:
      WRECON_BUFFER_HOOKED = False
      weechat.unhook(WRECON_HOOK_BUFFER)
    return weechat.WEECHAT_RC_OK
  
  #
  ##### END HOOK AND UNHOOK BUFFER
  
  #####
  #
  # AND HOOK COMMAND
  
  WRECON_HOOK_LOCAL_COMMAND = weechat.hook_command(SCRIPT_NAME, SCRIPT_DESC, SCRIPT_ARGS, SCRIPT_ARGS_DESCRIPTION, SCRIPT_COMPLETION, SCRIPT_CALLBACK, '')
  
  #####
  #
  # TRY CONNECT AUTOMATICALLY (in case we have registered CHANNEL & SERVER)

  f_autoconnect()
