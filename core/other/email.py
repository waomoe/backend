import smtplib
from os import getenv, path, listdir


class Email:
    smtp = smtplib.SMTP(
        getenv("SMTP_HOST", "localhost"),
        int(getenv("SMTP_PORT", 25)),
        local_hostname="localhost",
    )

    def __init__(self, from_addr, app):
        self.from_addr = from_addr
        self.app = app

    def send(
        self,
        to: str,
        message_content: str,
        subject: str,
        from_addr: str = None,
        **format,
    ) -> None:
        if message_content in self.presets.keys():
            message_content = str(self.presets[message_content]).format(**format)
        elif self.app.tl(message_content) != message_content:
            message_content = (self.app.tl(message_content)).format(**format)
        self.app.debug(
            f'Sending email with subject "{subject}" to {to}; message: {message_content[:50]}...'
        )
        self.smtp.sendmail(
            from_addr or self.from_addr, to, f"Subject: {subject}\n\n{message_content}"
        )

    presets = {}
    for filename in listdir(path.join(path.dirname(__file__) + "/email_presets/")):
        if filename.endswith(".txt") or filename.endswith(".html"):
            presets[".".join(filename.split(".")[:-1])] = open(
                path.join(path.dirname(__file__) + "/email_presets", filename), "r"
            ).read()
