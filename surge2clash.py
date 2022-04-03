#!/usr/bin/env python3
import sys
import logging
from yaml import dump
from typing import Union, Any, Dict

ConfigSection = Dict[str, Union[str, None]]
SurgeConfig = Dict[str, ConfigSection]


def parse_surge_config(data: str) -> SurgeConfig:
    lines = data.split('\n')
    global_config = {}
    section_config = {}
    section = 'Global'
    for line in lines:
        stripped_line = line.strip()
        if stripped_line.startswith('#'):
            continue
        if stripped_line.startswith('[') and stripped_line.endswith(']'):
            global_config[section] = section_config
            section = stripped_line.strip('[]')
            section_config = {}
            continue
        pos = stripped_line.find('=')
        if pos == -1:
            section_config[stripped_line] = None
            continue
        key = stripped_line[:pos].strip()
        val = stripped_line[pos+1:].strip()
        section_config[key] = val
    global_config[section] = section_config
    return global_config


def surge_general_to_clash(cfg: Any, section: ConfigSection) -> Any:
    def port_from_addr(x): return int(x.split(':')[1])
    for (key, val) in section.items():
        if key == 'interface':
            cfg['bind-address'] = val
        elif key == 'http-listen':
            cfg['port'] = port_from_addr(val)
        elif key == 'socks5-listen':
            cfg['socks-port'] = port_from_addr(val)
    return cfg


def surge_proxy_to_clash(cfg: Any, section: ConfigSection) -> Any:
    def build_proxy(name: str, line: str):
        seqs = list(map(lambda x: x.strip(), line.split(',')))
        if len(seqs) < 5:
            logging.warn('invalid proxy config {}'.format(line))
            return None
        type_map = {'https': 'http'}
        return {
            'name': name,
            'type': seqs[0] if seqs[0] not in type_map else type_map[seqs[0]],
            'server': seqs[1],
            'port': seqs[2],
            'tls': seqs[0] in ['https'],
            'username': seqs[3],
            'password': seqs[4],
        }
    proxies = []
    if 'proxies' in cfg:
        proxies = cfg['proxies']
    for (name, line) in section.items():
        if line is None:
            continue
        proxy = build_proxy(name, line)
        if proxy is None:
            continue
        proxies.append(proxy)
    cfg['proxies'] = proxies
    return cfg


def surge_proxy_group_to_clash(cfg: Any, section: ConfigSection) -> Any:
    def build_proxy_group(name: str, line: str):
        seqs = list(map(lambda x: x.strip(), line.split(',')))
        return {
            'name': name,
            'type': seqs[0],
            'proxies': seqs[1:],
        }
    proxy_groups = []
    if 'proxy-groups' in cfg:
        proxy_groups = cfg['proxy-groups']
    for (name, line) in section.items():
        if line is None:
            continue
        proxy_group = build_proxy_group(name, line)
        proxy_groups.append(proxy_group)
    cfg['proxy-groups'] = proxy_groups
    return cfg


def surge_rule_to_clash(cfg: Any, section: ConfigSection) -> Any:
    def build_rule(line: str):
        seqs = list(map(lambda x: x.strip(), line.split(',')))
        seqs = seqs[:4] if len(
            seqs) == 4 and seqs[3] == 'no-resolve' else seqs[:3]
        if seqs[0] in ['DOMAIN-SUFFIX',
                       'DOMAIN-KEYWORD',
                       'DOMAIN',
                       'IP-CIDR',
                       'GEOIP']:
            return ','.join(seqs)
        if seqs[0] == 'FINAL':
            return 'MATCH,Proxy'
    rules = [] if 'rules' not in cfg else cfg['rules']
    for line in section.keys():
        rule = build_rule(line)
        if rule is None:
            continue
        rules.append(rule)
    cfg['rules'] = rules
    return cfg


SURGE_TO_CLASH_MAP = {
    'General': surge_general_to_clash,
    'Proxy': surge_proxy_to_clash,
    'Proxy Group': surge_proxy_group_to_clash,
    'Rule': surge_rule_to_clash,
}


def surge_to_clash(surge_data: str) -> str:
    surge_config = parse_surge_config(surge_data)
    clash_config = {}
    for (name, section) in surge_config.items():
        if name not in SURGE_TO_CLASH_MAP:
            continue
        convert_fn = SURGE_TO_CLASH_MAP[name]
        clash_config = convert_fn(clash_config, section)
    output = dump(clash_config, allow_unicode=True)
    return output


def main():
    print(surge_to_clash(sys.stdin.read()))


if __name__ == "__main__":
    main()
