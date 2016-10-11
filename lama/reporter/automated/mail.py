__author__ = "Valentin Giannini"
__copyright__ = "Copyright 2016, LAMA"
__credits__ = [""]
__license__ = "GPL"
__version__ = "3"
__maintainer__ = "Valentin Giannini - CSE Team"
__email__ = "cse.contact -at- post.lu"
__status__ = "Production"


import smtplib
import logging
import configparser

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from lama.models.analysis import Analysis
from lama.reporter.automated_reporter import AutomatedReporter


class MailReporter(AutomatedReporter):

    if __name__ == '__main__':
        # get configuration for mail server
        config = configparser.ConfigParser()
        config.read('lama/conf/project.conf')
        try:
            enabled = config["MAIL_ALERT"]["enabled"].lower() == "true"
            user = config["MAIL_ALERT"]["user"]
            password = config["MAIL_ALERT"]["password"]
            sender = config["MAIL_ALERT"]["sender"]
            recipients = None
            if len(config["MAIL_ALERT"]["recipients"].strip()):
                recipients = [mail.strip() for mail in config["MAIL_ALERT"]["recipients"].split(",")]
            server = config["MAIL_ALERT"]["server"]
            smtp_port = config["MAIL_ALERT"]["smtp_port"]
        except KeyError as e:
            logging.error("Error project.conf[MAIL_ALERT] : {} missing.".format(str(e)))
            exit(1)

        # get information about LAMA plateform
        try:
            lama_host = config['LAMA']['host']
            lama_port = config['LAMA']['port']
        except KeyError as e:
            logging.error("Error project.conf[LAMA] : {} missing.".format(str(e)))
            exit(1)

    def run(self, analysis):
        """
        Run report function.
        If the score is higher than Analysis.ALERT_THRESHOLD it send a mail.
        """
        if MailReporter.enabled and MailReporter.recipients:

            # Send mail if dangerous !!!
            send_mail = False
            for m in analysis.malwares:
                stat = m.compute_stat()
                if stat['score_avg'] >= Analysis.ALERT_THRESHOLD:
                    send_mail = True
                    break
            if send_mail:
                server = smtplib.SMTP(MailReporter.server, MailReporter.smtp_port)
                server.starttls()
                server.login(MailReporter.user, MailReporter.password)

                msg = MIMEMultipart()
                msg['From'] = MailReporter.sender
                msg['To'] = ", ".join(MailReporter.recipients)
                msg['Subject'] = "Malware detected ({})".format(analysis.uid)

                if MailReporter.lama_port == 80:
                    url = "http://{}".format(MailReporter.lama_host)
                else:
                    url = "http://{}:{}".format(MailReporter.lama_host, MailReporter.lama_port)

                body = "Malware detected <br/>See <a href=\"http://{}/analyze/report/{}/html\">this link</a> for more informations.<br/>LAMA.".format(url, analysis.uid)
                msg.attach(MIMEText(body, 'html'))

                text = msg.as_string()
                server.sendmail(msg['From'], MailReporter.recipients, text)
                server.quit()
