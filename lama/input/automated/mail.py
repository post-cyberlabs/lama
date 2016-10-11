import os
import time
import email
import imaplib

from lama.utils.file import File
from lama.input.input import Input

__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


class Mail(object):

    def __init__(self, user, password, server, port):
        self._user = user
        self._password = password
        self._server = server
        self._port = port

    def run(self):
        self._connect_imap()
        while(True):
            self._retreive()
            time.sleep(1)

    def _connect_imap(self):
        print("CONNECTION ...")
        self._mail_server = imaplib.IMAP4_SSL(self._server)
        self._mail_server.login(self._user, self._password)

    def _retreive(self):
        self._mail_server.select("INBOX")
        typ, msgs = self._mail_server.search(None, '(UNSEEN)')
        msgs = msgs[0].split()
        paths = []
        filenames = []
        for num, emailid in enumerate(msgs):
            resp, data = self._mail_server.fetch(emailid, "(RFC822)")
            email_body = data[0][1]
            m = email.message_from_string(email_body.decode("utf-8"))

            sender = m['From']
            received_date = m['Date']
            subject = m['Subject']

            print("{} | {} | {}".format(sender, received_date, subject))

            if m.get_content_maintype() != 'multipart':
                continue

            for part in m.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                if part.get('Content-Disposition') is None:
                    continue

                filename = part.get_filename()
                if filename is not None:
                    content = part.get_payload(decode=True)
                    tmp_path = File.create_tmp_binary_file(filename, content)
                    tmp_file_path = os.path.join(tmp_path, filename)
                    print(tmp_file_path)
                    paths.append(tmp_path)
                    filenames.append(tmp_file_path)

        if len(filenames):
            inp = Input(filenames)
            analysis_id = inp.analyze()
            print("Analysis UID : {}".format(analysis_id))
            for p in paths:
                File.remove_tmp_dir(p)
