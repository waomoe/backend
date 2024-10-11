import smtplib


class Email:
    smtp = smtplib.SMTP('localhost', 25, local_hostname='localhost')
    
    def send(self, email: str, subject: str, message: str = '', message_html: str = '', preset: str = None, from_email: str = 'no-reply@wao.moe', **format):
        if not message and not message_html and not preset:
            raise ValueError('Either message, preset or message_html must be provided')
        if message_html:
            message = message_html
        if preset:
            message = open(f'core/other/email-presets/{preset}' + '' if '.html' in preset else '.html', 'r').read()
        self.smtp.sendmail(from_email, email, f'Subject: {subject}\n\n{message}'.format(**format))
    
    class Presets:
        pass
    
    def __repr__(self):
        return f'{self.smtp.local_hostname}:{self.smtp.default_port}'
    