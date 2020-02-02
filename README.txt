Weechat Remote Controll

Author  : Radek Valasek
Contact : radek.valasek.75@gmail.com
Licence : GPL3
GIT     : https://github.com/reddy75/wrecon

---

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, see <http://www.gnu.org/licenses/>.

---

Purpose:
Start 'tmate' session on remote PC over Weechat.
- tmate session is started only for granted server(s)
- communication between servers is accomplished over a registered IRC #Channel
- IRC #Channel is encrypted via ircrypt


Dependencies:
Weechat, Tmate, Python3, Python3 modules - ast, base64, datetime, hashlib, os, random, string, sys, time, weechat


Limitations:
- only one IRC #Channel with IRC Server is allowed to register
- supported platform is only linux and android (9/10 - with termux installed)


Tested on platform:
- Fedora 30/31
- Xubuntu 18.04
- Android 9/10 (in termux)
