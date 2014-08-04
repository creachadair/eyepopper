`eyepopper.py` implements a read-only POP3 proxy that presents a read-only view of
a collection of Unix [mbox](http://en.wikipedia.org/wiki/Mbox) files
or [Maildir](http://cr.yp.to/proto/maildir.html) directories.

Once upon a time, Apple's Mail.app did not understand how to read these files; more recent
versions are reputed to be able to handle mbox files, although I haven't tried it lately.
