from rule import Rule


class RuleMaker:
    def __init__(self, filePath):
        self.rules = []
        with open(filePath, 'r') as f:
            while True:
                line = f.readline()
                if not line:
                    break
                self.rules.append(Rule(line))

    def getRules(self):
        return self.rules
