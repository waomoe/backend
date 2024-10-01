import smtplib


class Email:
    smtp = smtplib.SMTP('localhost', 25, local_hostname='localhost')
    
    def send(self, email: str, subject: str, message: str = '', message_html: str = '', from_email: str = 'no-reply@wao.moe'):
        if not message and not message_html:
            raise ValueError('Either message or message_html must be provided')
        if message:
            message = message
        if message_html:
            message = f'<html><body>{message_html}</body></html>'
        self.smtp.sendmail(from_email, email, f'Subject: {subject}\n\n{message}')
    
    class Presets:
        pass