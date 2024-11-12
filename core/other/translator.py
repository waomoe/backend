from os import getcwd, listdir


class Translator:
    def __init__(self):
        """
        Initialize the Translator object

        This method initializes the Translator object by setting an empty dictionary as the tlbook.
        """
        self.tlbook = {}

    def chache_translations(self):
        """
        Cache all translations in memory

        This function reads all files in localization folder and stores all translations in tlbook.
        The structure of the tlbook is:
        {
            "locale_name": {
                "KEY": "translated value"
            }
        }
        """
        locales = listdir(getcwd() + "/localization")
        for locale in locales:
            with open(getcwd() + f"/localization/{locale}", "r") as locale_file:
                if locale.split(".")[0] not in self.tlbook:
                    self.tlbook[locale.split(".")[0]] = {}
                for line in locale_file.readlines():
                    self.tlbook[locale.split(".")[0]][
                        line.split("=")[0].strip().upper()
                    ] = self.translate_string(
                        line.split("=")[0].strip(), locale.split(".")[0]
                    )
                    if (
                        self.tlbook[locale.split(".")[0]][
                            line.split("=")[0].strip().upper()
                        ]
                        == line.split("=")[0].strip()
                    ):
                        del self.tlbook[locale.split(".")[0]][
                            line.split("=")[0].strip().upper()
                        ]

    def translate_string(self, key: str, language: str = "EN") -> str:
        with open(getcwd() + f"/localization/{language.upper()}.txt", "r") as locale:
            for line in locale.readlines():
                if "=" in line and line.split("=")[0].strip().upper() == key.upper():
                    return (
                        line[line.index("=") + 1 :]
                        .replace("\\n", "\n")
                        .replace("\\t", "\t")
                    )
        if language.upper() != "EN":
            return self.translate_string(key, "EN")
        return key

    def tl(self, key: str, language: str = "EN") -> str:
        """
        Translate a given key to the given language.

        Args:
            key (str): The key to translate.
            language (str, optional): The language to translate to. Defaults to 'EN'.

        Returns:
            str: The translated string.

        Notes:
            If the key is not found in the given language, it will fall back to English.
            If the key is not found in English either, it will return the key as is.
        """
        try:
            return self.tlbook[language.upper()][key.upper()]
        except Exception:
            return self.translate_string(key, language)
