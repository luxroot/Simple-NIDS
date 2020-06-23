from rule import Rule


class RuleMaker:
    def __init__(self, file_path):
        self.rules = []
        with open(file_path, 'r') as f:
            while True:
                line = f.readline().strip()
                if not line:
                    break
                self.rules.append(Rule(line))

    def get_rules(self):
        return self.rules
