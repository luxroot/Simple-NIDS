from netaddr import IPNetwork


class IPNetwork:
    def __init__(self, text):
        if text == "any":
            self.any = True
        else:
            self.any = False
            self.ipn = IPNetwork(text)

    def match(self, ip):
        return self.any or ip in self.ipn
