from netaddr import IPNetwork as IPN


class IPNetwork:
    def __init__(self, text):
        if text == "any":
            self.any = True
        else:
            self.any = False
            self.ipn = IPN(text)

    def __repr__(self):
        if self.any:
            return "IP of any"
        else:
            return "IP of "+str(self.ipn)

    def match(self, ip):
        return self.any or ip in self.ipn
