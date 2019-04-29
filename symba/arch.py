"""Info dictionaries to store architecture-dependent values
in object-like fashion.
"""


class Win32(dict):
    def __init__(self):
        # ? Is there any better way to initialize this dictionary? Probably, yep.
        types = {'WORD': 2, 'LPDWORD': 4}
        self.update(**types)

        super().__init__()

    def __getattr__(self, type):
        if type in self:
            return self[type]
        else:
            raise AttributeError(f"No such data type: {type}")
