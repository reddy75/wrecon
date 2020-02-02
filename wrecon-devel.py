# -*- coding: utf-8 -*-
# CODING=UTF8
#
# Weechat Remote Controll
# ======================================================================
# Author       : Radek Valasek
# Contact      : radek.valasek.75@gmail.com
# License      : GPL3
# GIT          : https://github.com/reddy75/wrecon
# Description  : Script for controll remote server
# Requirements : weechat, python3, tmate, ircrypt (script for weechat)

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
# 1.01 - Validation improvement
#        - static length of random generated string replaced by generating 
#          string of dynamic length (for better security purpose)
# 1.00 - First release

## PURPOSE
# Purpose of script is to start a 'tmate' session on remote server
#
#
## !!! IMPORTANT NOTE BEFORE USING - ENLIGHTENMENT AND RECOMMENDATION !!!
# - Is always your responsibility how you handle with secret information.
# - Keep in mind - be careful what and where you share information, particularly
# secret information about your configurations of #Channel KEY, #Channel encrypt KEY,
# BOT ID's and BOT KEY's.
# - Information should be secret, and can be known only to person you fully trust.
# - Secret information share by secure channel, for example by encrypted email.
# - In case a secret information (any part of setup of your wrecon) leaked then
# is recommended to change this information immediatelly.
# - Keep in mind, that every message in buffer are logged according to your setup
# of Weechat, and based on setup log level 9 (default) can be retrieved all information
# of your setup (for example, displayed result of command /wrecon me) 
# - Script was designed for home purpose only.
# - Script can be used in your company/organisation also, but ensure you have
# proper approval of your company/organisation.
# - Ensure, you have also installed 'ircrypt' and is automatically loaded in Weechat
# - Ensure, your Weechat have enabled Secure data with password protected. Wrecon
# using Secure data for storing important variables.
# - Choice strong #Channel KEY and strong #Channel encrypt KEY for your #Channel.
# (Check limitation of length of IRC Server for a #Channel KEY). Is recommended
# use longest #Channel KEY as possible.
# - Author of script is not responsible for any security incidents or difficulties caused by using script.
#
#
## LIMITATIONS
# Script allows you to register only one #Channel with one IRC Server (there is
# no plan to change it)
# Script is written in Python3 and there is no plan to support lower version of Python
# Script is written for linux systems and was written only for Weechat
# Script BOT's are communicating only through registered #Channel (communication
# PROTOCOL can not be hidden, because script is working with BUFFER only, and final
# encryption/decryption of all messages is provided by 'ircrypt')
# 
#
## SCRIPT WAS TESTED ON FOLLOWING PLATFORMS
# - Fedora 30/31
# - Xubuntu 18.04
# - Android 9/10 (in termux)
#
#
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
# Now your wrecon is prepared to controll Server B from Server A, and you can try
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
SCRIPT_VERSION   = '1.01 devel'
SCRIPT_TIMESTAMP = '20200201163051CET'
SCRIPT_AUTHOR    = 'Radek Valasek <radek.valasek.75@gmail.com>'
SCRIPT_LICENSE   = 'GPL3'
SCRIPT_DESC      = 'Weechat Remote Controll (WRECON)'
SCRIPT_UNLOAD    = 'wrecon_unload'

SCRIPT_CONTINUE  = True
import importlib
for import_mod in ['weechat', 'string', 'random', 'time', 'sys', 'hashlib', 'base64', 'ast', 'datetime', 'os']:
  if type(import_mod) is str:
    try:
      import_object = importlib.import_module(import_mod, package=None)
      globals()[import_mod] = import_object
      # ~ print('[%s v%s] > module %s imported' % (SCRIPT_NAME, SCRIPT_VERSION, import_mod))
    except ImportError:
      SCRIPT_CONTINUE = False
      print('[%s v%s] > module %s import error' % (SCRIPT_NAME, SCRIPT_VERSION, import_mod))
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
  # FUNCTION FOR GENERATING RANDOM CHARACTERS AND NUMBERS
  
  def f_random_generator(mylength):
    lettersAndDigits = string.ascii_letters + string.digits
    return ''.join(random.choice(lettersAndDigits) for i in range(mylength))
  
  #####
  #
  # FUNCTION FOR COUNTING COMMANDS
  
  def f_command_counter():
    global wrecon_command_counter
    wrecon_command_counter = wrecon_command_counter + 1
    if wrecon_command_counter > 999:
      wrecon_command_counter = 0
    return '%03d-%s' % (wrecon_command_counter, f_random_generator(3))
  
  #####
  #
  # FUNCTION FOR CHECK MY NICK IS OP AND CHANNEL CAN BE UPDATE IF NECESSARY
  def f_change_modeop(data, buffer, servername, channelname):
    global wrecon_channel_key
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
        if not wrecon_channel_key in my_channel_mode:
          resultchan = 1
        if not 'k' in my_channel_mode:
          resultmode = 1
        
    weechat.infolist_free(infolist)
    
    if resultnick == 1:
      if resultmode == 1 or resultchan == 1:
        weechat.command(buffer, '/mode %s -n+sk %s' % (channelname, wrecon_channel_key))
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
    global wrecon_bot_name, wrecon_bot_id
    f_message_simple(data, buffer, '--- %s (%s %s) ---' % (message_tag, wrecon_bot_name, wrecon_bot_id))
    for my_index in range(0, len(message), 1):
      f_message_simple(data, buffer, '%s' % (message[my_index]))
    return weechat.WEECHAT_RC_OK
  #
  ##### END FUNCTIONS FOR LOCAL MESSAGES
  
  
  #####
  #
  # FUNCTION GET BUFFERS AND BUFFER OF REGISTERED CHANNEL
  
  def f_get_buffers():
    wrecon_buffers  = {}
    infolist_buffer = weechat.infolist_get('buffer', '', '')
    while weechat.infolist_next(infolist_buffer):
      buffer_pointer              = weechat.infolist_pointer(infolist_buffer, 'pointer')
      buffer_name                 = weechat.buffer_get_string(buffer_pointer, 'localvar_name')
      wrecon_buffers[buffer_name] = buffer_pointer
    weechat.infolist_free(infolist_buffer)
    return wrecon_buffers
  
  def f_get_buffer_channel():
    global wrecon_server, wrecon_channel
    wrecon_buffer_name = '%s.%s' % (wrecon_server, wrecon_channel)
    wrecon_buffers     = f_get_buffers()
    if wrecon_buffer_name in wrecon_buffers:
      return wrecon_buffers[wrecon_buffer_name]
    else:
      return ''
  
  #
  ##### END FUNCTION GET BUFFERS AND BUFFER OF REGISTERED CHANNEL
  
  
  #####
  #
  # FUNCTIONS AUTOCONNECT
  # 1) test we are connected to registered server - (connect automatically)
  # 2) test we are joined to registered channel - (join automatically)
  
  def f_autoconnect():
    global wrecon_server, wrecon_channel
    if wrecon_server and wrecon_channel:
      if f_get_status_server() == 0:
        f_autoconnect_server()
      else:
        v_buffer_server = f_get_buffers()
        f_autoconnect_channel(v_buffer_server['server.%s' % (wrecon_server)])
    return weechat.WEECHAT_RC_OK
  
  def f_get_status_server():
    global wrecon_server
    infolist_server = weechat.infolist_get('irc_server', '', '')
    server_status   = {}
    while  weechat.infolist_next(infolist_server):
      server_name                = weechat.infolist_string(infolist_server, 'name')
      server_stat                = weechat.infolist_integer(infolist_server, 'is_connected')
      server_status[server_name] = server_stat
    weechat.infolist_free(infolist_server)
    
    if wrecon_server in server_status:
      return server_status[wrecon_server]
    else:
      return '0'
  
  def f_get_status_channel():
    global wrecon_server, wrecon_channel
    infolist_channel  = weechat.infolist_get('irc_channel', '', wrecon_server)
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
        if channel_field_name == 'buffer_short_name' and channel_field_value == wrecon_channel:
          do_record = True
        elif channel_field_name == 'buffer_short_name' and channel_field_value != wrecon_channel:
          do_record = False
        if do_record == True:
          channel_status[channel_field_name] = channel_field_value
    weechat.infolist_free(infolist_channel)

    if 'nicks_count' in channel_status:
      return channel_status['nicks_count']
    else:
      return 0
  
  def f_get_server_setup():
    global wrecon_server
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
        f_message_simple('', '', 'SETUP - %s - %s : %s' % (wrecon_server, server_field_name, server_field_value))
    weechat.infolist_free(infolist_server)
    return server_status
    
  def f_autoconnect_server():
    global wrecon_server
    weechat.command('', '/connect %s' % (wrecon_server))
    wrecon_hook_connect = weechat.hook_timer(1*1000, 0, 20, 'f_autoconnect_server_status', '')
    return weechat.WEECHAT_RC_OK
  
  def f_autoconnect_server_status(arg1, arg2):
    global wrecon_server
    if f_get_status_server() == 1:
      weechat.unhook(wrecon_hook_connect)
      wrecon_buffers = f_get_buffers()
      f_autoconnect_channel(wrecon_buffers['server.%s' % (wrecon_server)])
    return weechat.WEECHAT_RC_OK
  
  def f_autoconnect_channel(buffer):
    global wrecon_channel, wrecon_channel_key, wrecon_hook_join, wrecon_server 
    weechat.command(buffer, '/join %s %s' % (wrecon_channel, wrecon_channel_key))
    wrecon_hook_join = weechat.hook_timer(1*1000, 0, 5, 'f_autoconnect_channel_status', '')
  
  def f_autoconnect_channel_status(arg1, arg2):
    global wrecon_hook_join, wrecon_auto_advertised, wrecon_hook_buffer, wrecon_buffer_channel, SCRIPT_CALLBACK_BUFFER
    
    if arg2 == '0':
      weechat.unhook(wrecon_hook_join)
    
    if f_get_status_channel() > 0:
      weechat.unhook(wrecon_hook_join)
      if wrecon_auto_advertised == False:
        f_buffer_hook()
        f_autoconnect_channel_mode(wrecon_buffer_channel)
        command_advertise('', wrecon_buffer_channel, '')
        wrecon_auto_advertised = True
    return weechat.WEECHAT_RC_OK
  
  def f_autoconnect_channel_mode(buffer):
    global wrecon_channel, wrecon_channel_key, wrecon_server
    f_change_modeop('', buffer, wrecon_server, wrecon_channel)
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
    global wrecon_server, wrecon_channel, wrecon_bot_name, wrecon_bot_id, wrecon_buffer_channel
    weechat.buffer_set(wrecon_buffer_channel, 'title', 'Weechat Remote Controll - %s - %s - %s [%s]' % (wrecon_server, wrecon_channel, wrecon_bot_name, wrecon_bot_id))
    return weechat.WEECHAT_RC_OK
  
  #
  ##### END FUNCTION CHANGE BUFFER TITLE
  
  #####
  #
  # INITIALIZATION OF BASIC VARIABLES FOR BOT
  
  global wrecon_default_botnames, wrecon_bot_name, wrecon_bot_id, wrecon_bot_key
  wrecon_default_botnames = ['anee', 'anet', 'ann', 'annee', 'annet', 'bob', 'brad', 'don', 'fred', 'freddie', 'john', 'mia', 'moon', 'pooh', 'red', 'ron', 'ronnie', 'shark', 'ted', 'teddy', 'zed', 'zoe', 'zombie']
  wrecon_bot_name         = weechat.string_eval_expression("${sec.data.wrecon_bot_name}",{},{},{})
  wrecon_bot_id           = weechat.string_eval_expression("${sec.data.wrecon_bot_id}",{},{},{})
  wrecon_bot_key          = weechat.string_eval_expression("${sec.data.wrecon_bot_key}",{},{},{})
  #
  # Choice default BOT NAME if not exist and save it
  #
  if not wrecon_bot_name:
    wrecon_bot_name = random.choice(wrecon_default_botnames)
    weechat.command('','/secure set wrecon_bot_name %s' % (wrecon_bot_name))
  #
  #  Generate BOT ID if not exit and save it
  #
  if not wrecon_bot_id:
    wrecon_bot_id = f_random_generator(16)
    weechat.command('','/secure set wrecon_bot_id %s' % (wrecon_bot_id))
  #
  # Generate BOT KEY if not exist and save it
  #
  if not wrecon_bot_key:
    wrecon_bot_key = f_random_generator(64)
    weechat.command('','/secure set wrecon_bot_key %s' % (wrecon_bot_key))
  
  #
  #
  ##### BOT INITIALIZATION IS DONE
  
  # ~ mytext      = 'a toto je test'
  # ~ mymessage   = f_encrypt_string(mytext, wrecon_bot_key)
  # ~ print('TEST : %s' % (mymessage))
  
  # ~ mymessage2  = f_decrypt_string(mymessage, wrecon_bot_key)
  # ~ print('TEST : %s' % (mymessage2))
  
  #####
  #
  # INITIALIZATION OF BASIC VARIABLES FOR SERVER AND CHANNEL
  
  global wrecon_server, wrecon_channel, wrecon_channel_key, wrecon_channel_encryption_key, wrecon_buffers, wrecon_buffer_channel, wrecon_command_counter, wrecon_auto_advertised, wrecon_buffer_hooked
  wrecon_server                 = weechat.string_eval_expression("${sec.data.wrecon_server}",{},{},{})
  wrecon_channel                = weechat.string_eval_expression("${sec.data.wrecon_channel}",{},{},{})
  wrecon_channel_key            = weechat.string_eval_expression("${sec.data.wrecon_channel_key}",{},{},{})
  wrecon_channel_encryption_key = weechat.string_eval_expression("${sec.data.wrecon_channel_encryption_key}",{},{},{})
  wrecon_buffers                = {}
  wrecon_buffer_channel         = ''
  wrecon_command_counter        = 0
  wrecon_auto_advertised        = False
  wrecon_buffer_hooked          = False
  
  #####
  #
  # BASIC VARIABLES OF REGISTERED REMOTE BOTS
  #
  # CONTROLL   - bots you can controll remotely on remote system
  #              table contain BOT IDs and it's BOT KEYs
  #
  # GRANTED    - bots from remote system can controll your system (you grant controol of your system)
  #              table contain only BOT IDs
  #
  # VERIFIED   - runtime variable of bots from remote system can controll your system only after verification
  #              table contain BOT IDs and additional info from irc_channel of related NICK
  #              in case information of remote NICK will be changed, then new verification will be triggered
  #
  # ADVERTISED - runtime variable of bots which has been advertised in channel, it is only informational and for internal purpose to
  #              have actual state
  #              table contain BOT IDs and BOT NAMEs only
  
  global wrecon_remote_bots_controll, wrecon_remote_bots_granted, wrecon_remote_bots_verified, wrecon_remote_bots_advertised
  wrecon_remote_bots_controll   = weechat.string_eval_expression("${sec.data.wrecon_remote_bots_controll}",{},{},{})
  wrecon_remote_bots_granted    = weechat.string_eval_expression("${sec.data.wrecon_remote_bots_granted}",{},{},{})
  wrecon_remote_bots_verified   = {}
  wrecon_remote_bots_advertised = {}
  
  if wrecon_remote_bots_controll:
    wrecon_remote_bots_controll = ast.literal_eval(wrecon_remote_bots_controll)
  else:
    wrecon_remote_bots_controll = {}
  
  if wrecon_remote_bots_granted:
    wrecon_remote_bots_granted = ast.literal_eval(wrecon_remote_bots_granted)
  else:
    wrecon_remote_bots_granted = {}
  
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
  %(bold)s%(underline)sWeechat Remote Controll (WRECON) commands and options:%(nunderline)s%(nbold)s
  ''' % COLOR_TEXT

  #####
  #
  # INITIALIZE HOOK VARIABLES FOR WHOLE SCRIPT
  
  global wrecon_hook_command, wrecon_hook_connect, wrecon_hook_join, wrecon_hook_buffer, wrecon_hook_local_commands
  wrecon_hook_command        = ''
  wrecon_hook_connect        = ''
  wrecon_hook_join           = ''
  wrecon_hook_buffer         = ''
  wrecon_hook_local_commands = ''


  #####
  #
  # COMMANDS - ALL COMMANDS
  
  #####
  #
  # COMMAND ADD REMOTE BOT YOU WILL CONTROLL
  
  def command_add_controlled_bot(data, buffer, args):
    global wrecon_remote_bots_controll
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
      if new_remote_bot_id in wrecon_remote_bots_controll:
        f_message(data, buffer, v_err_topic, ['ALREADY ADDED. First DEL, then ADD.'])
      else:
        wrecon_remote_bots_controll[new_remote_bot_id] = [new_remote_bot_key, new_remote_bot_note]
        weechat.command(buffer, '/secure set wrecon_remote_bots_controll %s' % (wrecon_remote_bots_controll))
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
  Add remote bot for your controll. By command ADVERTISE you will know %(italic)sbotid%(nitalic)s, but the %(italic)sbotkey%(nitalic)s you need receive by safe way.''' % COLOR_TEXT + '''
  Oposit of command ADD is command DEL.
    /wrecon ADD %s %s
    /wrecon ADD %s %s %s
    ''' % (f_random_generator(16), f_random_generator(64), f_random_generator(16), f_random_generator(64), random.choice(wrecon_default_botnames))
  SCRIPT_COMPLETION          = SCRIPT_COMPLETION + ' || ADD'
  SCRIPT_COMMAND_CALL['add'] = command_add_controlled_bot
  
  #
  ##### END COMMAND ADD REMOTE BOT YOU WILL CONTROLL
  

  #####
  #
  # COMMAND ADVERTISE
  
  global BUFFER_CMD_ADV_EXE, BUFFER_CMD_ADV_REP, BUFFER_CMD_ADV_ERR, BUFFER_CMD_ADA_EXE, BUFFER_CMD_ADA_REP
  BUFFER_CMD_ADV_EXE = '%sE-ADV' % (COMMAND_IN_BUFFER)
  BUFFER_CMD_ADV_REP = '%sADV-R' % (COMMAND_IN_BUFFER)
  BUFFER_CMD_ADV_ERR = '%sADV-E' % (COMMAND_IN_BUFFER)
  BUFFER_CMD_ADA_EXE = '%sE-ADA' % (COMMAND_IN_BUFFER)
  BUFFER_CMD_ADA_REP = '%sADA-R' % (COMMAND_IN_BUFFER)
  
  def command_advertise(data, buffer, args):
    global BUFFER_CMD_EADV, BUFFER_CMD_ADV_REP, wrecon_bot_id, uniq_hash, wrecon_bot_name, SCRIPT_VERSION, SCRIPT_TIMESTAMP
    uniq_hash = f_command_counter()
    # PROTOCOL: COMMAND TO_BOTID|HASH FROM_BOTID HASH [DATA]
    
    # debugging - remove after debugging >>>
    global wrecon_server, wrecon_channel
    f_change_modeop(data, buffer, wrecon_server, wrecon_channel)
    # debugging - remove after debugging <<<
    
    weechat.command(buffer, '%s %s %s %s v%s %s' % (BUFFER_CMD_ADV_EXE, uniq_hash, wrecon_bot_id, uniq_hash, SCRIPT_VERSION, SCRIPT_TIMESTAMP))
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
    global BUFFER_CMD_ADV_REP, wrecon_bot_id, wrecon_bot_name, SCRIPT_VERSION, SCRIPT_TIMESTAMP
    # PROTOCOL: COMMAND TO_BOTID|HASH FROM_BOTID HASH [DATA]
    v_check_is_hash       = args[0]
    v_remote_bot_id       = args[1]
    v_remote_bot_hash_cmd = args[2]
    if v_check_is_hash == v_remote_bot_hash_cmd:
      weechat.command(buffer, '%s %s %s %s %s [v%s %s]' % (BUFFER_CMD_ADV_REP, v_remote_bot_id, wrecon_bot_id, v_remote_bot_hash_cmd, wrecon_bot_name, SCRIPT_VERSION, SCRIPT_TIMESTAMP))
    else:
      global BUFFER_CMD_ADV_ERR
      weechat.command(buffer, '%s %s %s %s [v%s %s] ERROR - PROTOCOL VIOLATION' % (BUFFER_CMD_ADV_ERR, v_remote_bot_id, wrecon_bot_id, v_remote_bot_hash_cmd, SCRIPT_VERSION, SCRIPT_TIMESTAMP))
    return weechat.WEECHAT_RC_OK
  
  def receive_advertise(data, buffer, tags, prefix, args):
    global wrecon_remote_bots_advertised
    # PROTOCOL: COMMAND TO_BOTID|HASH FROM_BOTID HASH [DATA]
    v_remote_bot_id   = args[1]
    v_bot_hash_cmd    = args[2]
    v_remote_bot_name = f_get_name(1, args)
    v_remote_bot_data = '%s|%s' % (v_remote_bot_name, f_get_nick_info(tags, prefix))
    wrecon_remote_bots_advertised[v_remote_bot_id] = v_remote_bot_data
    f_message_simple(data, buffer, 'REMOTE BOT REGISTERED : %s (%s)' % (v_remote_bot_id, v_remote_bot_name))
    return weechat.WEECHAT_RC_OK
  
  def receive_advertise_error(data, buffer, tags, prefix, args):
    global wrecon_remote_bots_advertised
    if args[1] in wrecon_remote_bots_advertised:
      del wrecon_remote_bots_advertised[args[1]]
    f_message_simple(data, buffer, 'REMOTE BOT UNREGISTERED : %s' % (args[1]))
    return weechat.WEECHAT_RC_OK
  
  def reply_advertise_additionally(data, buffer, tags, prefix, args):
    global BUFFER_CMD_ADA_REP, wrecon_bot_name, SCRIPT_VERSION, SCRIPT_TIMESTAMP
    f_message_simple(data, buffer, 'RECEIVED ADDITIONAL ADVERTISE from %s' % (args[1]))
    weechat.command(buffer, '%s %s %s %s %s [%s-%s]' % (BUFFER_CMD_ADA_REP, args[1], args[0], args[2], wrecon_bot_name, SCRIPT_VERSION, SCRIPT_TIMESTAMP))
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
  # COMMAND DELETE REMOTE BOT FROM CONTROLL
  
  def command_del_controll_bot(data, buffer, args):
    global wrecon_remote_bots_controll
    v_err       = False
    v_err_topic = 'DELETE ERROR'
    if args:
      if len(args) == 1:
        if args[0] in wrecon_remote_bots_controll:
          del wrecon_remote_bots_controll[args[0]]
          weechat.command(buffer, '/secure set wrecon_remote_bots_controll %s' % (wrecon_remote_bots_controll))
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
  Delete remote bot from your controll.
    /wrecon DEL %s
  ''' % (f_random_generator(16))
  SCRIPT_COMPLETION             = SCRIPT_COMPLETION + ' || DEL || DELETE'
  SCRIPT_COMMAND_CALL['del']    = command_del_controll_bot
  SCRIPT_COMMAND_CALL['delete'] = command_del_controll_bot
  
  #
  ##### END COMMAND DELETE REMOTE BOT FROM CONTROLL


  #####
  #
  # COMMAND GRANT
  
  def command_grant_bot(data, buffer, args):
    global wrecon_remote_bots_granted
    v_err       = False
    v_err_topic = 'GRANT ERROR'
    if len(args) >= 1:
      new_remote_bot_id  = args[0]
      if len(args) == 1:
        wrecon_remote_bots_granted[new_remote_bot_id] = ''
      else:
        args.pop(0)
        wrecon_remote_bots_granted[new_remote_bot_id] = ' '.join(map(str, args))
      weechat.command(buffer, '/secure set wrecon_remote_bots_granted %s' % (wrecon_remote_bots_granted))
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
  Opposit of command GRANT is command REVOKE.
    /wrecon GRANT %s
    /wrecon G %s
    /wrecon G %s %s
    ''' % (f_random_generator(16), f_random_generator(16), f_random_generator(16), random.choice(wrecon_default_botnames))
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
RENAME     M[YBOT]| botid a new name
REVOKE     R[EVOKE] botid
SSH        S[SH] botid
UNREGISTER UNREG[ISTER]

<<<BriefHelp
  '''
  
  def command_help(data, buffer, args):
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
  
  def command_list_bot(data, buffer, args):
    global wrecon_remote_bots_controll, wrecon_remote_bots_granted, wrecon_remote_bots_advertised
    v_err       = False
    v_err_topic = 'LIST ERROR'
    v_topic     = 'LIST INFO'
    if len(args) == 1:
      v_param = args[0].lower()
      if v_param in ['a', 'added', 'g', 'granted']:
        out_message = []
        if v_param in ['a', 'added']:
          if wrecon_remote_bots_controll:
            for reg_bot in wrecon_remote_bots_controll:
              if len(wrecon_remote_bots_controll[reg_bot]) == 1:
                out_msg = reg_bot
              else:
                out_msg = '%s - %s' % (reg_bot, wrecon_remote_bots_controll[reg_bot][1])
              if reg_bot in wrecon_remote_bots_advertised:
                out_msg = out_msg + ' (%s)' % wrecon_remote_bots_advertised[reg_bot].split('|')[0]
              out_message.append(out_msg)
            f_message(data, buffer, '%s ADDED BOTS' % (v_topic), out_message)
          else:
            f_message(data, buffer, '%s ADDED BOTS' % (v_topic), ['No registered remote bots'])
        else:
          if wrecon_remote_bots_granted:
            for reg_bot in wrecon_remote_bots_granted:
              if len(wrecon_remote_bots_granted[reg_bot]) == 0:
                out_msg = reg_bot
              else:
                out_msg = '%s - %s' % (reg_bot, wrecon_remote_bots_granted[reg_bot])
              if reg_bot in wrecon_remote_bots_advertised:
                out_msg = out_msg + ' (%s)' % (wrecon_remote_bots_advertised[reg_bot]).split('|')[0]
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
  List of ADDED bots you can controll, or GRANTED bots which can controll your system.
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
  
  def command_me(data, buffer, args):
    global wrecon_server, wrecon_channel, wrecon_channel_key, wrecon_channel_encryption_key, wrecon_bot_name, wrecon_bot_id, wrecon_bot_key, SCRIPT_VERSION, SCRIPT_TIMESTAMP
    info_message     = ['Bot Name  : %s' % (wrecon_bot_name)]
    info_message.append('Bot ID    : %s' % (wrecon_bot_id))
    info_message.append('Bot KEY   : %s' % (wrecon_bot_key))
    info_message.append('VERSION   : %s' % (SCRIPT_VERSION))
    info_message.append('TIMESTAMP : %s' % (SCRIPT_TIMESTAMP))
    if wrecon_channel and wrecon_server:
      info_message.append('--- REGISTERED SERVER and CHANNEL ---')
      info_message.append('SERVER                 : %s' % (wrecon_server))
      info_message.append('CHANNEL                : %s' % (wrecon_channel))
      info_message.append('CHANNEL KEY            : %s' % (wrecon_channel_key))
      info_message.append('CHANNEL ENCRYPTION KEY : %s' % (wrecon_channel_encryption_key))
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
  
  def command_register_channel(data, buffer, args):
    v_err = False
    if len(args) == 2:
      global wrecon_channel, wrecon_server, wrecon_channel_key, wrecon_channel_encryption_key, wrecon_buffer_channel
      if wrecon_server and wrecon_channel:
        v_err = True
      else:
        wrecon_channel_key            = args[0]
        wrecon_channel_encryption_key = args[1]
        wrecon_server                 = weechat.buffer_get_string(buffer, 'localvar_server')
        wrecon_channel                = weechat.buffer_get_string(buffer, 'localvar_channel')
        wrecon_buffer_channel         = buffer
        v_message_out     = ['SERVER                 : %s' % (wrecon_server)]
        v_message_out.append('CHANNEL                : %s' % (wrecon_channel))
        v_message_out.append('CHANNEL KEY            : %s' % (wrecon_channel_key))
        v_message_out.append('CHANNEL ENCRYPTION KEY : %s' % (wrecon_channel_encryption_key))
        f_message(data, buffer, 'REGISTER INFO', v_message_out)
        weechat.command(buffer, '/secure set wrecon_server %s' % (wrecon_server))
        weechat.command(buffer, '/secure set wrecon_channel %s' % (wrecon_channel))
        weechat.command(buffer, '/secure set wrecon_channel_key %s' % (wrecon_channel_key))
        f_change_modeop(data, buffer, wrecon_server, wrecon_channel)
        weechat.command(buffer, '/secure set wrecon_channel_encryption_key %s' % (wrecon_channel_encryption_key))
        weechat.command(buffer, '/ircrypt set-key -server %s %s %s' % (wrecon_server, wrecon_channel, wrecon_channel_encryption_key))
        weechat.command(buffer, '/ircrypt set-cipher -server %s %s aes256' % (wrecon_server, wrecon_channel))
        
        f_buffer_hook()
        
        save_options = False
        wrecon_server_autoconnect   = weechat.string_eval_expression("${irc.server.%s.autoconnect}" % (wrecon_server), {}, {}, {})
        wrecon_server_autoreconnect = weechat.string_eval_expression("${irc.server.%s.autoreconnect}" % (wrecon_server), {}, {}, {})
        wrecon_channel_autojoin     = weechat.string_eval_expression("${irc.server.%s.autojoin}" % (wrecon_server), {}, {}, {}).split(',')
        wrecon_channel_autorejoin   = weechat.string_eval_expression("${irc.server.%s.autorejoin}" % (wrecon_server), {}, {}, {})
        
        if wrecon_server_autoconnect != 'on':
          weechat.command(buffer, '/set irc.server.%s.autoconnect on' % (wrecon_server))
          save_options = True
        
        if wrecon_server_autoreconnect != 'on':
          weechat.command(buffer, '/set irc.server.%s.autoreconnect on' % (wrecon_server))
          save_options = True
        
        if wrecon_channel_autorejoin != 'on':
          weechat.command(buffer, '/set irc.server.%s.autorejoin on' % (wrecon_server))
          save_options = True
        
        channel_index = [i for i, elem in enumerate(wrecon_channel_autojoin) if wrecon_channel in elem]
        if not channel_index:
          wrecon_channel_autojoin.append('%s ${sec.data.wrecon_channel_key}' % (wrecon_channel))
          wrecon_channel_autojoinx = ','.join(map(str, wrecon_channel_autojoin))
          weechat.command(buffer, '/set irc.server.%s.autojoin %s' % (wrecon_server, wrecon_channel_autojoinx))
          save_option = True
        else:
          wrecon_channel_autojoin[channel_index[0]] = '%s ${sec.data.wrecon_channel_key}' % (wrecon_channel)
          wrecon_channel_autojoinx = ','.join(map(str, wrecon_channel_autojoin))
          weechat.command(buffer, '/set irc.server.%s.autojoin %s' % (wrecon_server, wrecon_channel_autojoinx))
          save_option = True
        
        if save_options == True:
          weechat.command(buffer, '/save')
    else:
      v_err = True
    if v_err == True:
      if wrecon_server and wrecon_channel:
        f_message(data, buffer, 'REGISTER ERROR', ['ALREADY REGISTERED > First UNREGISTER, then REGISTER again.'])
      else:
        f_message(data, buffer, 'REGISTER ERROR', ['MISSING PARAMETERS > 2 expected. See help.'])
    return weechat.WEECHAT_RC_OK
  
  SCRIPT_ARGS                     = SCRIPT_ARGS + ' | [REG[ISTER] <CHANNEL_KEY> <ENCRYPT_KEY>]'
  SCRIPT_ARGS_DESCRIPTION         = SCRIPT_ARGS_DESCRIPTION + '''
  %(bold)s%(italic)s--- REGISTER <channel_key> <encrypt_key>%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
  Register current channel for controlling remote bot's. You have to be actively connected to server and joined in channel you need register.
  Opposit of command REGISTER is command UNREGISTER.
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
    global wrecon_bot_name, wrecon_server, wrecon_channel, wrecon_bot_id, REMOTE_ADVERTISED
    REMOTE_ADVERTISED = False
    weechat.command(buffer,'/secure set wrecon_bot_name %s' % (newname))
    wrecon_bot_name = newname
    info_message = ['Your bot Name has been changed to \'%s\'' % (newname)]
    f_change_buffer_title()
    f_message(data, buffer, 'RENAME INFO', info_message)
    command_advertise(data, buffer, '')
    return weechat.WEECHAT_RC_OK
  

  def command_rename(data, buffer, args):
    v_err       = False
    v_err_topic = 'RENAME ERROR'
    v_topic     = 'RENAME INFO'
    if args:
      if len(args) >= 2:
        global wrecon_bot_newname, wrecon_buffer_channel, uniq_hash
        if args[0].lower() == 'm' or args[0].lower() == 'mybot':
          f_save_new_name(data, wrecon_buffer_channel, f_get_name(0, args))
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
    ''' % (random.choice(wrecon_default_botnames), f_random_generator(16), random.choice(wrecon_default_botnames), random.choice(wrecon_default_botnames))
  SCRIPT_COMPLETION             = SCRIPT_COMPLETION + ' || REN || RENAME'
  SCRIPT_COMMAND_CALL['ren']    = command_rename
  SCRIPT_COMMAND_CALL['rename'] = command_rename
  
  def command_rename_remote(data, buffer, args):
    global wrecon_bot_id
    # Check if bot id belong to own bot
    if args[0] == wrecon_bot_id:
      f_save_new_name(data, buffer, f_get_name(0, args))
    else:
      # Check if bot is registered
      global wrecon_remote_bots_controll
      if args[0] in wrecon_remote_bots_controll:
        global BUFFER_CMD_REN_EXE, uniq_hash_cmd_rename
        uniq_hash_cmd_rename = f_command_counter()
        # PROTOCOL: COMMAND TO_BOT_ID FROM_BOT_ID HASH [DATA]
        weechat.command(buffer, '%s %s %s %s %s' % (BUFFER_CMD_REN_EXE, args[0], wrecon_bot_id, uniq_hash_cmd_rename, f_get_name(0, args)))
      else:
        f_message(data, buffer, 'RENAME ERROR', ['REMOTE BOT %s IS NOT REGISTERED' % (args[0])])
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
  
  def command_revoke(data, buffer, args):
    global wrecon_remote_bots_granted
    v_err       = False
    v_err_topic = 'REVOKE ERROR'
    v_topic     = 'REVOKE INFO'
    if len(args) == 1:
      if args[0] in wrecon_remote_bots_granted:
        del wrecon_remote_bots_granted[args[0]]
        weechat.command(buffer, '/secure set wrecon_remote_bots_granted %s' % (wrecon_remote_bots_granted))
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
  Revoke granted access to your system for bot.
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
  
  def command_ssh(data, buffer, args):
    global wrecon_remote_bots_controll
    v_err       = False
    v_err_topic = 'SSH ERROR'
    v_topic     = 'SSH INFO'
    # PROTOCOL: COMMAND TO_BOT_ID FROM_BOT_ID HASH [DATA]
    if len(args) == 1:
      global wrecon_remote_bots_controll
      # 1. Check we have registered remote bot
      if not args[0] in wrecon_remote_bots_controll:
        f_message(data, buffer, v_err_topic, ['REMOTE BOT %s IS NOT REGISTERED' % (args[0])])
      else:
        global wrecon_remote_bots_advertised
        # 2. Check remote bot has been advertised
        if not args[0] in wrecon_remote_bots_advertised:
          f_message(data, buffer, v_err_topic, ['REMOTE BOT %s WAS NOT ADVERTISED' % (args[0])])
        else:
          global wrecon_bot_id, BUFFER_CMD_SSH_EXE
          uniq_hash_cmd_ssh = f_command_counter()
          weechat.command(buffer, '%s %s %s %s' % (BUFFER_CMD_SSH_EXE, args[0], wrecon_bot_id, uniq_hash_cmd_ssh))
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
      global SSH_HOOK_PROCESS, SSH_PROCESS_DATA, BUFFER_CMD_SSH_REP, wrecon_bot_key, BUFFER_CMD_SSH_REK
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
        message_encrypted = f_encrypt_string(out_message, wrecon_bot_key)
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
    global wrecon_remote_bots_controll, BUFFER_CMD_SSH_REK, SSH_GLOBAL_OUTPUT
    remote_bot_id = args[1]
    if BUFFER_CMD_SSH_REK in args:
      f_message_simple(data, buffer, '')
      v_data  = SSH_GLOBAL_OUTPUT[0].split('|')[0]
      v_topic = 'SSH INFO (%s)' % (v_data)
      OUT_MSG = ['>>> START MESSAGE from %s : %s' % (remote_bot_id, args[2])]
      OUT_MSG.append('')
      for O_M in SSH_GLOBAL_OUTPUT:
        OUT_MSG.append('%s' % (O_M.split('|')[1]))
      OUT_MSG.append('')
      OUT_MSG.append('END OF MESSAGE from %s : %s <<<' % (remote_bot_id, args[2]))
      OUT_MSG.append('')
      f_message(data, buffer, v_topic, OUT_MSG)
      # ~ f_message_simple(data, buffer, '%s : %s' % (args[2], dec_message))
      SSH_GLOBAL_OUTPUT = []
    else:
      dec_key     = wrecon_remote_bots_controll[remote_bot_id][0]
      dec_message = f_decrypt_string(args[3], wrecon_remote_bots_controll[args[1]][0])
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
  
  def command_unregister_channel(data, buffer, args):
    global wrecon_channel, wrecon_server, wrecon_channel_key, wrecon_channel_encryption_key
    v_err = False
    if wrecon_channel and wrecon_server:
      save_options = False
      wrecon_channel_autojoin     = weechat.string_eval_expression("${irc.server.%s.autojoin}" % (wrecon_server), {}, {}, {}).split(',')
      
      channel_index = [i for i, elem in enumerate(wrecon_channel_autojoin) if wrecon_channel in elem]
      if channel_index:
        del wrecon_channel_autojoin[channel_index[0]]
        wrecon_channel_autojoinx = ','.join(map(str, wrecon_channel_autojoin))
        weechat.command(buffer, '/set irc.server.%s.autojoin %s' % (wrecon_server, wrecon_channel_autojoinx))
        save_option = True
        
      if save_options == True:
        weechat.command(buffer, '/save')
      
      f_buffer_unhook()
      
      weechat.command(buffer, '/secure del wrecon_server')
      weechat.command(buffer, '/secure del wrecon_channel')
      weechat.command(buffer, '/secure del wrecon_channel_key')
      weechat.command(buffer, '/secure del wrecon_channel_encryption_key')
      weechat.command(buffer, '/ircrypt remove-key -server %s %s' % (wrecon_server, wrecon_channel))
      weechat.command(buffer, '/ircrypt remove-cipher -server %s %s' % (wrecon_server, wrecon_channel))
      unreg_message     = ['Channel and server unregistered.']
      unreg_message.append('In case you no longer need current channel (%s), remove key from channel by following command:' % (wrecon_channel))
      unreg_message.append('/mode %s -k' % (wrecon_channel))
      f_message(data, buffer, 'UNREGISTER', unreg_message)
      wrecon_channel                = ''
      wrecon_server                 = ''
      wrecon_channel_encryption_key = ''
      wrecon_channel_key            = ''
    else:
      v_err = True
    if v_err == True:
      f_message(data, buffer, 'UNREGISTER ERROR', ['No server and channel is registered.'])
    return weechat.WEECHAT_RC_OK
  
  SCRIPT_ARGS                       = SCRIPT_ARGS + ' | [UNREG[ISTER]]'
  SCRIPT_ARGS_DESCRIPTION           = SCRIPT_ARGS_DESCRIPTION + '''
  %(bold)s%(italic)s--- UNRE[GISTER]%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
  Unregister channel of controlling remote bot's.
  '''
  SCRIPT_COMPLETION                 = SCRIPT_COMPLETION + ' || UNREG || UNREGISTER'
  SCRIPT_COMMAND_CALL['unreg']      = command_unregister_channel
  SCRIPT_COMMAND_CALL['unregister'] = command_unregister_channel
  
  #
  ##### END COMMAND UNREGISTER CHANNEL
  
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
    global wrecon_bot_id
    if args[1] == wrecon_bot_id:
      call_requested_function(data, buffer, tags, prefix, args)
    else:
      # ~ global wrecon_remote_bots_advertised, wrecon_remote_bots_granted, wrecon_remote_bots_verified
      # args:
      # 0 - TO BOT ID
      # 1 - FROM BOT ID
      # 2 - HASH
      # 3 - [DATA]
      # 
      # 1. check remote bot is granted
      global wrecon_remote_bots_granted
      if not args[1] in wrecon_remote_bots_granted:
        reply_validation_error(data, buffer, 'ACCESS IS NOT GRANTED', args)
      else:
        # 2. check remote bot was advertised
        global wrecon_remote_bots_advertised, ADDITIONAL_ADVERTISE
        if not args[1] in wrecon_remote_bots_advertised:
          global ADDITIONAL_ADVERTISE
          additional_key = '%s%s' % (args[1], args[2])
          if not additional_key in ADDITIONAL_ADVERTISE:
            # Initiate additional advertise of remote bot
            global BUFFER_CMD_ADA_EXE, SCRIPT_VERSION, SCRIPT_TIMESTAMP
            weechat.command(buffer, '%s %s %s %s [v%s %s]' % (BUFFER_CMD_ADA_EXE, args[1], args[0], args[2], SCRIPT_VERSION, SCRIPT_TIMESTAMP))
            ADDITIONAL_ADVERTISE[additional_key] = [call_requested_function, data, buffer, tags, prefix, args]
          else:
            # In case remote bot has been additionally asked for advertisement and was not advertised, then it is error (script on remote site stopped or stuck)
            reply_validation_error(data, buffer, 'PROTOCOL VIOLATION - REMOTE BOT WAS NOT ADVERTISED', args)
            del ADDITIONAL_ADVERTISE[additional_key]
        else:
          # 3. check remote bot was verified
          global wrecon_remote_bots_verified, BUFFER_CMD_VAL_FUNCTION
          v_validated = False
          v_command_key = '%s%s' % (args[1], args[2])
          if args[1] in wrecon_remote_bots_verified:
            # 4. execute function when bot was properly validated
            if wrecon_remote_bots_verified[args[1]] == wrecon_remote_bots_advertised[args[1]]:
              global BUFFER_CMD_VAL_REA
              v_validated = True
              weechat.command(buffer, '%s %s %s %s EXECUTION ACCEPTED' % (BUFFER_CMD_VAL_REA, args[1], args[0], args[2]))
              if v_command_key in BUFFER_CMD_VAL_FUNCTION:
                del BUFFER_CMD_VAL_FUNCTION[v_command_key]
              call_requested_function(data, buffer, tags, prefix, args)
          if v_validated == False:
            # Ensure validation
            global wrecon_bot_key, BUFFER_CMD_VAL_EXE
            random_len = random.randint(23, 31)
            generate_seecret = f_random_generator(random_len)
            send_secret = f_encrypt_string(generate_seecret, wrecon_bot_key)
            BUFFER_CMD_VAL_FUNCTION[v_command_key] = [generate_seecret, call_requested_function, tags, prefix, args]
            weechat.command(buffer, '%s %s %s %s %s' % (BUFFER_CMD_VAL_EXE, args[1], args[0], args[2], send_secret))
            # ~ weechat.command(buffer, 'Wi will do a validation... %s' % (args))
      
    return weechat.WEECHAT_RC_OK
  
  # ~ BUFFER_CMD_VAL_EXE
  def receive_validation(data, buffer, tags, prefix, args):
    global wrecon_remote_bots_controll, BUFFER_CMD_VAL_REP
    decrypt_key      = wrecon_remote_bots_controll[args[1]][0]
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
      global wrecon_bot_key
      decrypt_hash = f_decrypt_string(args[3], wrecon_bot_key)
      stored_hash  = f_get_hash(BUFFER_CMD_VAL_FUNCTION[v_command_key][0])
      if decrypt_hash == stored_hash:
        f_message_simple(data, buffer, 'VALIDATION SUCCESSFUL')
        global wrecon_remote_bots_advertised, wrecon_remote_bots_verified
        wrecon_remote_bots_verified[args[1]] = wrecon_remote_bots_advertised[args[1]]
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
        SCRIPT_COMMAND_CALL[v_command](data, buffer, v_datasend)
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
      global BUFFER_CMD_ADV_EXE, wrecon_bot_id
      v_arguments.pop(0)
      # Check the command from buffer is for advertisement or it belong to our BOT
      if v_cmd == BUFFER_CMD_ADV_EXE or v_arguments[0] == wrecon_bot_id:
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
    global SCRIPT_CALLBACK_BUFFER, wrecon_buffer_hooked, wrecon_hook_buffer, wrecon_buffer_channel
    wrecon_buffer_channel = f_get_buffer_channel()
    if wrecon_buffer_hooked == False:
      if wrecon_buffer_channel:
        wrecon_buffer_hooked = True
        wrecon_hook_buffer    = weechat.hook_print(wrecon_buffer_channel, '', COMMAND_IN_BUFFER, 1, SCRIPT_CALLBACK_BUFFER, '')
    return weechat.WEECHAT_RC_OK
  
  def f_buffer_unhook():
    global wrecon_buffer_hooked, wrecon_hook_buffer
    if wrecon_buffer_hooked == True:
      wrecon_buffer_hooked = False
      weechat.unhook(wrecon_hook_buffer)
    return weechat.WEECHAT_RC_OK
  
  #
  ##### END HOOK AND UNHOOK BUFFER
  
  #####
  #
  # AND HOOK COMMAND
  
  #info_message     = ['NAME : ' + SCRIPT_NAME]
  #info_message.append('DESC : ' + SCRIPT_DESC)
  #info_message.append('ARGS : ' + SCRIPT_ARGS)
  #info_message.append('ARGD : ' + SCRIPT_ARGS_DESCRIPTION)
  #info_message.append('COMP : ' + SCRIPT_COMPLETION)
  #info_message.append('CALL : ' + SCRIPT_CALLBACK)
  #f_message('','','INFO', info_message)
  wrecon_hook_local_commands = weechat.hook_command(SCRIPT_NAME, SCRIPT_DESC, SCRIPT_ARGS, SCRIPT_ARGS_DESCRIPTION, SCRIPT_COMPLETION, SCRIPT_CALLBACK, '')
  
  #####
  #
  # IN CASE WE HAVE REGISTERED SERVER AND CHANNEL, WE WILL CONNECT THERE AUTOMATICALLY
  
  f_autoconnect()
