class Port:
    def __init__(self, text):
        if text == "any":
            self.any = True
        else:
            self.any = False
            if ':' in text:
                start, end = text.split(':')
                start = 0 if start == '' else int(start)
                end = 65535 if end == '' else int(end)
                self.portList = range(start, end + 1)
            elif ',' in text:
                self.portList = map(int, text.split(','))
            else:
                self.portList = [int(text)]

    def __repr__(self):
        if self.any:
            return "Port of any"
        else:
            return "Port of "+str(list(self.portList))

    def match(self, port):
        return self.any or port in self.portList
