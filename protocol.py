class Protocol():
    def __init__(self, text):
        if text not in ['tcp', 'udp', 'http', 'any']:
            raise ValueError
        if text == 'any':
            self.any = True
        else:
            self.any = False
        self.protocol = text

    def match(self, packet):
        if self.any:
            return True

