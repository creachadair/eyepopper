#!/usr/bin/env python3
# -*- coding: utf-8 -*-
##
## Name:     eyepopper.py
## Purpose:  Simple mailbox-to-POP3 gateway.
##
## Copyright © 2002 Michael J. Fromberger.  All rights reserved.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions are met:
##
## 1. Redistributions of source code must retain the above copyright notice,
##    this list of conditions and the following disclaimer.
##
## 2. Redistributions in binary form must reproduce the above copyright notice,
##    this list of conditions and the following disclaimer in the documentation
##    and/or other materials provided with the distribution.
##
## THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR IMPLIED
## WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
## MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
## EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
## SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
## PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
## OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
## WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
## OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
## ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
##
from __future__ import with_statement

from socketserver import TCPServer, StreamRequestHandler
import getopt, hashlib, os, random, re, socket, sys, time

__version__ = "1.5"
MBOX_ENCODING = 'latin-1'


class MessageBase(object):
    """Base class representing a message stored in a Unix mailbox file.
    Subclasses must override:

    ._data    -- the complete mailbox data (string).
    ._path    -- the pathname of the mailbox file (string).

    Instances provide the following attributes:
    .start    -- position of first character of message
    .end      -- position after last character of message
    .poplen   -- length of message including CRLF conversion
    .bodypos  -- position of first character of mesage body
    .uid      -- unique identifier for message
    .content  -- the complete content of the message (computed)
    .head     -- the headers of the message (computed)
    .body     -- the body of the message (computed)
    """

    def __init__(self, start, end):
        self.start = start
        self.end = end

        text = self._data[start:end]
        self.poplen = (end - start) + len(re.findall(r'\n', text))
        self.bodypos = end
        bmark = re.search(r'\n\n', text)
        if bmark:
            self.bodypos = start + bmark.end()

        hash = hashlib.md5()
        hash.update(text.encode(MBOX_ENCODING))
        hash.update(self._path.encode('utf-8'))

        self.uid = hash.hexdigest()

    def get_content(self):
        return self._data[self.start:self.end]

    def get_head(self):
        return self._data[self.start:self.bodypos]

    def get_body(self):
        return self._data[self.bodypos:self.end]

    def get_top(self, n):
        """As .get_content(), but return at most n lines from the
        beginning of the message body, n >= 0.
        """
        assert n >= 0

        lines = self.body.split('\n')
        return self.head + '\n'.join(lines[:n])

    content = property(get_content, None, None,
                       "Return the complete content of the message.")
    head = property(get_head, None, None, "Return the headers of the message.")
    body = property(get_body, None, None, "Return the body of the message.")


class MailContainer(object):
    """Abstracts a Maildir mailbox stored on disk."""

    def __init__(self, path):
        """Constructs a new mailbox abstraction around the given
        filesystem object, a file or a directory.
        """
        self._path = os.path.realpath(path)
        self.build_index()

    def __len__(self):
        """Count the number of messages in this mailbox."""
        return len(self._msgs)

    def __getitem__(self, itm):
        """Fetch a message by index."""
        return self._msgs[itm]

    def __iter__(self):
        """Iterate over all the messages in the mailbox."""
        return iter(self._msgs)

    def mailbox_path(self):
        """Return the pathname of the mailbox."""
        return self._path

    def mailbox_size(self):
        """Return the total size of the mailbox in octets."""
        return sum(m.poplen for m in self._msgs)


class MailboxFile(MailContainer):
    """Abstracts a Unix mailbox file stored on disk."""

    def build_index(self):
        """Construct an index of the contents of the associated disk file."""
        ex = re.compile(r'^(From \w+.*\n)\w+', re.MULTILINE | re.UNICODE)
        with open(self._path, 'rb') as fp:
            data = fp.read().decode(MBOX_ENCODING)

            class Message(MessageBase):
                _data = data
                _path = self._path

            msgs = [{'start': 0}]  # sentinel

            for msg in ex.finditer(data):
                msgs[-1]['end'] = msg.start()
                msgs.append({'start': msg.start() + len(msg.group(1))})

            msgs[-1]['end'] = len(data)
            if len(msgs) > 1:
                msgs.pop(0)

            self._msgs = list(Message(m['start'], m['end']) for m in msgs)
            self._data = data


class Maildir(MailContainer):
    """Abstracts a Maildir mailbox in a directory.
    """

    def build_index(self):
        cdir = os.path.join(self._path, 'cur')
        ndir = os.path.join(self._path, 'new')

        class Message(MessageBase):

            def __init__(self, data, path):
                self._data = data
                self._path = path
                super(Message, self).__init__(0, len(data))

        msgs = []
        for base in (cdir, ndir):
            for fname in os.listdir(base):
                fpath = os.path.join(base, fname)
                with open(fpath, 'r') as fp:
                    msgs.append(Message(fp.read(), fpath))

        self._msgs = msgs


class POP3Server(TCPServer):
    """Implements a simple read-only POP3 server."""
    allow_reuse_address = True
    capabilities = ['TOP', 'USER', 'UIDL']

    def __init__(self, port, mailboxes, **opts):
        """Create a new server instance.

        port         -- TCP port to listen on.
        mailboxes    -- MailboxFile objects to serve.
        debug        -- enable debugging output?
        allow_delete -- simulate deletion at exit?
        allow_apop   -- allow APOP authentication?
        """
        self._debug = opts.get('debug', False)
        self._host = 'localhost'
        self._port = port
        self._boxes = list(mailboxes)
        self._dels = set()
        self._users = dict(opts.get('users', ()))
        self._apopc = None

        self.allow_delete = opts.get('allow_delete', False)
        self.allow_apop = opts.get('allow_apop', False)

        TCPServer.__init__(self, (self._host, port), POP3Handler)

    def _diag(self, msg, *args):
        if self._debug:
            print(msg % args, file=sys.stderr)

    def run(self):
        """Run the server until it is killed or closed."""
        self.server_activate()
        self.running = True
        try:
            self._diag('* SERVER STARTING at %s %s', self._host, self._port)

            while self.running:
                # Choose a new APOP banner for each new session.
                ident = int(random.random() * os.getpid() * 10)
                self._apopc = '<{0}.{1}@{2}>'.format(ident, int(time.time()),
                                                     socket.gethostname())

                self.handle_request()

            self._diag('* SERVER SHUTTING DOWN')
        except KeyboardInterrupt:
            print("\n>> INTERRUPT <<", file=sys.stderr)
        finally:
            self.server_close()

    def mail_total_count(self):
        """[client] Return the total number of messages in all
        known mailboxes.
        """
        return sum(len(b) for b in self._boxes)

    def mail_total_size(self):
        """[client] Return the total size of the messages in all
        known mailboxes.
        """
        return sum(b.mailbox_size() for b in self._boxes)

    def mail_get_index(self, pos):
        """[client] Fetch a message object by its global index (0-based)."""
        if pos < 0:
            raise IndexError("Out of range")

        for mbox in self._boxes:
            if len(mbox) > pos:
                break

            pos -= len(mbox)
        else:
            raise IndexError("Out of range")

        return mbox[pos]

    def mail_get_all(self):
        """[client] Iterate over all the messages in all known mailboxes."""
        for mbox in self._boxes:
            for msg in mbox:
                yield msg

    def mail_mark_deleted(self, pos):
        """[client] Mark the specified message as "deleted"."""
        self.mail_get_index(pos)  # range test
        self._dels.add(pos)

    def mail_get_deleted(self):
        """[client] Return a set of indices of deleted messages."""
        return self._dels

    def mail_clear_deleted(self):
        """[client] Clear the list of "deleted" messages."""
        self._dels.clear()

    def mail_add_mailbox(self, path):
        """[client] Add a new mailbox to the list of known mailboxes."""
        for box in self._boxes:
            if box.mailbox_path() == path:
                return

        if os.path.isdir(path):
            box = Maildir(path)  # may fail
        else:
            box = MailboxFile(path)  # may fail
        self._boxes.append(box)

    def is_mail_deleted(self, pos):
        """[client] Check whether the message specified is "deleted"."""
        return pos in self._dels

    def is_user_ok(self, user):
        """[client] Check whether a user ID is acceptable."""
        return len(self._users) == 0 or user in self._users

    def is_auth_ok(self, user, pw):
        """[client] Check user authentication."""
        return len(self._users) == 0 or (user in self._users
                                         and self._users[user] == pw)

    def is_apop_ok(self, user, response):
        """[client] Check APOP authentication."""
        if len(self._users) == 0:
            return True
        elif user not in self._users:
            return False
        else:
            t = self.get_apop_tag() + self._users[user]
            m = hashlib.md5()
            m.update(t)
            return m.hexdigest().lower() == response.lower()

    def get_apop_tag(self):
        """[client] Return APOP challenge banner."""
        return self._apopc


class StateError(Exception):
    """An exception used internally by POP3Handler."""
    pass


class POP3Handler(StreamRequestHandler):
    """Implements a very simple POP3 service.

    In addition to the usual POP3 suite, this handler implements the
    following client commands:

    SHUTDOWN       -- close down the server immediately.
    ADDBOX <path>  -- load a new mailbox into the running server.
    """
    welcome_banner = 'POP3 server ready'
    want_shutdown = False

    def _put(self, text):
        self.wfile.write(text.encode('utf-8'))

    def cmd_unknown(self, cmd, data):
        """Handle unknown commands."""
        self._put('-ERR Command not understood\r\n')

    def _diag(self, msg, *args):
        self.server._diag(msg, *args)

    def check_state(self, cmd, data, state):
        if self.state != state:
            self._put('-ERR Invalid command\r\n')
            raise StateError

    def check_args(self, cmd, data, min, max):
        args = re.split(r'\s+', data) if data else []

        if min <= len(args) and (max < 0 or len(args) <= max):
            return args
        else:
            self._put('-ERR Wrong number of arguments (%s)\r\n' % cmd)
            raise StateError

    def parse_args(self, args):
        try:
            return list(int(x) for x in args)
        except ValueError:
            self._put('-ERR Invalid argument\r\n')
            raise StateError

    def check_message(self, pos):
        try:
            msg = self.server.mail_get_index(pos)
            if self.server.is_mail_deleted(pos):
                self._put('-ERR Message is deleted\r\n')
                raise StateError
            return msg
        except IndexError:
            self._put('-ERR Message out of range\r\n')
            raise StateError

    def send_data(self, data):
        esc = re.compile(r'^\.', re.MULTILINE | re.UNICODE)
        text = esc.sub('..', data.replace('\n', '\r\n'))
        self._put('+OK %d octets\r\n' % len(text))
        self._put(text)
        if not text.endswith('\r\n'):
            self._put('\r\n')
        self._put('.\r\n')

    def cmd_NOOP(self, cmd, data):
        self.check_args(cmd, data, 0, 0)
        self._put('+OK Nothing accomplished\r\n')

    def cmd_QUIT(self, cmd, data):
        self.check_args(cmd, data, 0, 0)
        self.state = 'UPDATE'  # triggers exit from handler loop
        self._diag('- Received QUIT command, entering UPDATE state.')

    def cmd_USER(self, cmd, data):
        try:
            self.check_state(cmd, data, 'AUTH')
            self.check_args(cmd, data, 1, 1)
            if self.server.is_user_ok(data):
                self._put('+OK %s\r\n' % data)
                self.state = 'USER'
                self.userid = data
            else:
                self._put('-ERR User invalid\r\n')
        except StateError:
            if self.state == 'USER':
                self.state = 'AUTH'

    def cmd_PASS(self, cmd, data):
        self.check_state(cmd, data, 'USER')
        self.check_args(cmd, data, 1, 1)
        if self.server.is_auth_ok(self.userid, data):
            self._put('+OK Ready\r\n')
            self.state = 'TRANS'
            self._diag('- Authenticated "%s", entering TRANSACTION state.',
                       self.userid)
        else:
            self._put('-ERR Access denied\r\n')
            self.state = 'AUTH'

    def cmd_APOP(self, cmd, data):
        if not self.server.allow_apop:
            self.cmd_unknown(cmd, data)
            return
        self.check_state(cmd, data, 'AUTH')
        self.userid, response = self.check_args(cmd, data, 2, 2)
        if self.server.is_apop_ok(self.userid, response):
            self._put('+OK Ready\r\n')
            self.state = 'TRANS'
            self._diag('- Authenticated "%s", entering TRANSACTION state.',
                       self.userid)
        else:
            self._put('-ERR Access denied\r\n')
            self.state = 'AUTH'

    def cmd_STAT(self, cmd, data):
        self.check_state(cmd, data, 'TRANS')
        self.check_args(cmd, data, 0, 0)
        self._put(
            '+OK %d %d\r\n' %
            (self.server.mail_total_count(), self.server.mail_total_size()))

    def list_cmd(extract):

        def do_command(self, cmd, data):
            self.check_state(cmd, data, 'TRANS')
            args = self.parse_args(self.check_args(cmd, data, 0, 1))
            if args:
                msg = self.check_message(args[0] - 1)
                elt = extract(msg)
                self._put('+OK %d %s\r\n' % (args[0], elt))
            else:
                self._put('+OK %d messages (%d octets)\r\n' %
                          (self.server.mail_total_count(),
                           self.server.mail_total_size()))
                for pos, msg in enumerate(self.server.mail_get_all()):
                    if not self.server.is_mail_deleted(pos):
                        elt = extract(msg)
                        self._put('%d %s\r\n' % (pos + 1, elt))
                self._put('.\r\n')

        return do_command

    cmd_LIST = list_cmd(lambda m: m.poplen)
    cmd_UIDL = list_cmd(lambda m: m.uid)

    def cmd_RETR(self, cmd, data):
        self.check_state(cmd, data, 'TRANS')
        args = self.parse_args(self.check_args(cmd, data, 1, 1))
        msg = self.check_message(args[0] - 1)
        self.send_data(msg.content)

    def cmd_DELE(self, cmd, data):
        self.check_state(cmd, data, 'TRANS')
        args = self.parse_args(self.check_args(cmd, data, 1, 1))
        msg = self.check_message(args[0] - 1)
        self.server.mail_mark_deleted(args[0] - 1)
        self._put('+OK Message %d deleted\r\n' % args[0])
        self._diag('- Marked message %d for deletion.', args[0])

    def cmd_RSET(self, cmd, data):
        self.check_state(cmd, data, 'TRANS')
        self.check_args(cmd, data, 0, 0)
        self.server.mail_clear_deleted()
        self._put('+OK Reset\r\n')
        self._diag('- Reset deleted messages list.')

    def cmd_TOP(self, cmd, data):
        self.check_state(cmd, data, 'TRANS')
        msgid, n = self.parse_args(self.check_args(cmd, data, 2, 2))

        if n < 0:
            self._put('-ERR Invalid argument\r\n')
            return

        msg = self.check_message(msgid - 1)
        self.send_data(msg.get_top(n))

    def cmd_CAPA(self, cmd, data):
        self.check_args(cmd, data, 0, 0)
        self._put('+OK Capability list follows\r\n')
        for cap in self.server.capabilities:
            self._put('%s\r\n' % cap)
        self._put('IMPLEMENTATION eyepopper.py v.%s\r\n' % __version__)
        self._put('.\r\n')

    def cmd_SHUTDOWN(self, cmd, data):
        self.check_state(cmd, data, 'TRANS')
        self.check_args(cmd, data, 0, 0)
        self.want_shutdown = True
        self._put('+OK Server will shut down at QUIT.\r\n')
        self._diag('- Client requested server SHUTDOWN.')

    def cmd_ADDBOX(self, cmd, data):
        self.check_state(cmd, data, 'TRANS')
        if not data or data.isspace():
            self._put('-ERR Invalid argument\r\n')
            return

        try:
            self.server.mail_add_mailbox(data)
            self._put('+OK Mailbox added %s\r\n' % data)
            self._diag('- Client requested mailbox "%s".', data)
        except (OSError, IOError) as e:
            self._put('-ERR Mailbox not added (%s)\r\n' % e.strerror)

    def handle(self):
        """Required entry point for use with SocketServer.  Dispatches
        received commands to .cmd_XXXX() methods based on the first
        word of the command line received from the client.

        Command names are case-insensitive, but the method names to
        implement them must be capitalized.  If .cmd_unknown() is
        defined, it is given all commands that are not otherwise
        recognized.

        Note: This implementation is not thread-safe; in particular,
        it uses state on the server object without locks.
        """
        try:
            self._put('+OK %s' % self.welcome_banner)
            if self.server.allow_apop:
                self._put(' %s' % self.server.get_apop_tag())
            self._put('\r\n')
            self.state = 'AUTH'
            self._diag('- Client connected, entering AUTH state.')

            while self.state != 'UPDATE':
                line = self.rfile.readline().decode('utf-8')
                args = line.rstrip().split(' ', 1)
                cmd = args[0]
                data = ''
                if len(args) > 1:
                    data = args[1]
                hname = 'cmd_%s' % cmd.upper()

                try:
                    getattr(self, hname, self.cmd_unknown)(cmd, data)
                except StateError:
                    pass

            if self.want_shutdown:
                self.server.running = False

            # When control reaches here, we are in the "UPDATE" state
            # of the POP3 protocol.  Since this is read-only, deleted
            # messages will not actually be removed; the POP3 RFC
            # wants this to be an error.
            if (len(self.server.mail_get_deleted()) == 0
                    or self.server.allow_delete):
                self._put('+OK Goodnight sweet prince\r\n')
            else:
                self._put('-ERR Unable to delete messages\r\n')
                self.server.mail_clear_deleted()

            self._diag('* REQUEST COMPLETE\n')

        except socket.error as e:
            pass

        self.wfile.close()
        self.rfile.close()


def main(argv):

    def usage(short=True):
        """Print a human-readable usage message."""
        print("Usage: eyepopper.py [options] mailbox*", file=sys.stderr)
        if short:
            print(" [use -h or --help for options]\n", file=sys.stderr)
        else:
            print("""
This program implements a local read-only POP3 server that serves up
messages stored in plain text mailbox files or directories in Maildir
format.  It can be used to import such messages into clients that do
not fully grok Unix mailbox format or Maildir.  For each mailbox path
given on the command line, if the path corresponds to a directory, it
is interpreted as a Maildir; otherwise as a Unix mailbox file.

Options:
  -h/--help             : display this help message.
  -a/--apop             : enable APOP authentication.
  -E/--noerror          : suppress error for deleted messages at exit.
  -p/--port <port>      : listen on the specified port (default: %s).
  -q/--quiet            : disable diagnostic output (run quietly)
  -u/--user <name>:<pw> : allow this username/password combination.

The POP_PORT environment variable will be used to specify the port, if
it is defined and the --port option is not provided.  Only one client
will be served at a time, and only clients connecting from localhost
are accepted.

By default, any username and password are accepted.  If the --user
option is used one or more times, only the user/password combinations
specified are granted access.  The name and password are separated by
a colon.  Username and password combinations can also be supplied via
the POP_USERS environment variable, where multiple entries are
delimited by carriage returns.
""" % listen_port,
                  file=sys.stderr)

    # Process command-line options
    try:
        opts, args = getopt.gnu_getopt(
            argv, 'haEp:qu:',
            ('help', 'apop', 'noerror', 'port=', 'quiet', 'user='))
    except getopt.GetoptError as e:
        print("Error: %s" % e, file=sys.stderr)
        usage()
        return 1

    listen_port = int(os.getenv('POP_PORT', 1110))
    debugging = True
    legal_users = {}
    allow_delete = False
    allow_apop = False
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage(short=False)
            return 0
        elif opt in ('-a', '--apop'):
            allow_apop = True
        elif opt in ('-E', '--noerror'):
            allow_delete = True
        elif opt in ('-q', '--quiet'):
            debugging = False
        elif opt in ('-p', '--port'):
            listen_port = int(arg)
        elif opt in ('-u', '--user'):
            try:
                name, pw = arg.strip().split(':', 1)
                legal_users[name] = pw
            except ValueError:
                print("Error: Invalid user specification: %s" % arg,
                      file=sys.stderr)
                usage()
                return 1
        else:
            raise NotImplementedError("unimplemented option")

    # Load users from the environment, if any are defined
    for line in os.getenv('POP_USERS', '').split('\n'):
        try:
            name, pw = line.strip().split(':', 1)
            legal_users[name] = pw
        except ValueError:
            pass  # skip quietly

    # Load mailbox files
    try:
        boxes = []
        for path in args:
            if os.path.isdir(path):
                boxes.append(Maildir(path))
            else:
                boxes.append(MailboxFile(path))
    except (OSError, IOError) as e:
        print("Error: %s" % e, file=sys.stderr)
        return 2

    # Start up server
    if debugging:
        print("EyePopper v. %s by M. J. Fromberger" % __version__,
              file=sys.stderr)
        if boxes:
            sys.stderr.write("Mailboxes:\n -")
            print("\n - ".join("%s (%d msg)" % (b.mailbox_path(), len(b))
                               for b in boxes),
                  file=sys.stderr)
            sys.stderr.write("\n")
        if legal_users:
            print("Legal users: %s\n" % ", ".join(legal_users),
                  file=sys.stderr)
        if allow_delete:
            print("Enabled: Simulated deletion", file=sys.stderr)
        if allow_apop:
            print("Enabled: APOP", file=sys.stderr)

    pop = POP3Server(listen_port,
                     boxes,
                     debug=debugging,
                     users=legal_users,
                     allow_delete=allow_delete,
                     allow_apop=allow_apop)
    pop.run()

    return 0


if __name__ == "__main__":
    res = main(sys.argv[1:])
    sys.exit(res)

# Here there be dragons
