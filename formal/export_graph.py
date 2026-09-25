#!/usr/bin/env python3
"""Translate TLC's DOT state graph, without reimplementing any protocol rule."""
import json
import re
import sys
from pathlib import Path

TOKEN = re.compile(r'\s*(<<|>>|:>|@@|[{}(),]|-?\d+|[A-Za-z_][A-Za-z_0-9]*|"(?:[^"\\]|\\.)*")')

class ValueParser:
    def __init__(self, text):
        self.tokens = []
        while text.strip():
            match = TOKEN.match(text)
            if not match:
                raise ValueError(f"Unsupported TLC value: {text!r}")
            self.tokens.append(match[1])
            text = text[match.end():]
        self.index = 0

    def pop(self, expected=None):
        token = self.tokens[self.index]
        self.index += 1
        if expected is not None and token != expected:
            raise ValueError(f"Expected {expected}, got {token}")
        return token

    def value(self):
        token = self.pop()
        if token in ('{', '<<'):
            end = '}' if token == '{' else '>>'
            result = []
            if self.tokens[self.index] != end:
                while True:
                    result.append(self.value())
                    if self.tokens[self.index] == end:
                        break
                    self.pop(',')
            self.pop(end)
            return result
        if token == '(':
            result = {}
            while True:
                key = str(self.value())
                self.pop(':>')
                if key in result:
                    raise ValueError('Duplicate map key')
                result[key] = self.value()
                if self.tokens[self.index] == ')':
                    break
                self.pop('@@')
            self.pop(')')
            return result
        if token in ('TRUE', 'FALSE'):
            return token == 'TRUE'
        if re.fullmatch(r'-?\d+', token):
            return int(token)
        return json.loads(token) if token.startswith('"') else token


def parse_value(text):
    parser = ValueParser(text)
    value = parser.value()
    if parser.index != len(parser.tokens):
        raise ValueError(f"Trailing tokens in {text}")
    return value


def export(path):
    states, edges, initial = {}, [], None
    label_pattern = r'"((?:[^"\\]|\\.)*)"'
    for line in Path(path).read_text().splitlines():
        edge = re.match(r'(-?\d+) -> (-?\d+) \[label=' + label_pattern, line)
        if edge:
            edges.append({'from': edge[1], 'to': edge[2], 'action': json.loads('"' + edge[3] + '"')})
            continue
        node = re.match(r'(-?\d+) \[label=' + label_pattern, line)
        if node:
            label = json.loads('"' + node[2] + '"')
            state = {}
            for assignment in re.split(r'/\\\s*', label):
                if not assignment.strip():
                    continue
                name, value = assignment.split(' = ', 1)
                state[name.strip()] = parse_value(value)
            states[node[1]] = state
            if 'style = filled' in line:
                if initial is not None:
                    raise ValueError('Multiple initial states require explicit support')
                initial = node[1]
            continue
        if re.match(r'-?\d+ ', line):
            raise ValueError(f'Unsupported TLC graph statement: {line}')
    if not initial or not states or not edges:
        raise ValueError('Missing initial state, states or labeled edges')
    for edge in edges:
        if edge['from'] not in states or edge['to'] not in states:
            raise ValueError(f'Unknown state in {edge}')
    return {'initial': initial, 'states': states, 'edges': edges}

if __name__ == '__main__':
    Path(sys.argv[2]).write_text(json.dumps(export(sys.argv[1])))
