import smtplib


class Email:
    smtp = smtplib.SMTP('localhost', 25, local_hostname='localhost')
    
    def send(self, email: str, subject: str, message: str = '', message_html: str = '', preset: str = None, from_email: str = 'no-reply@wao.moe', **kwargs):
        if not message and not message_html and not preset:
            raise ValueError('Either message, preset or message_html must be provided')
        if message_html:
            message = message_html
        if preset:
            message = open(f'core/other/email-presets/{preset}.html', 'r').read()
        self.smtp.sendmail(from_email, email, f'Subject: {subject}\n\n{message}'.format(**kwargs))
    
    class Presets:
        pass