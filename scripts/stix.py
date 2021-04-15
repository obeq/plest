import click
from rich import print
from rich.console import Console
from rich.table import Table
from rich.tree import Tree
import orjson
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk


class Malware(BaseModel):
    id: str
    name: Optional[str]
    created: datetime

    indicators: Optional[List] = []


class Indicator(BaseModel):
    id: str
    patterns: Dict[str,str]

    indicates: Optional[Malware]

    def to_es(self) -> Dict:
        obj = dict()
        obj['_id'] = self.id
        obj['_index'] = 'indicators'

        source = dict()
        source['indicates'] = self.indicates.id
        
        for key, value in self.patterns.items():
            source[key] = value

        obj['_source'] = source
        return obj


pattern_fields = {
    'url:value': 'url.full',
    "domain-name:value": 'url.domain',
    "file:hashes.MD5": 'hash.md5',
    "file:hashes.'SHA-1'": 'hash.sha1',
    "file:hashes.'SHA-256'": 'hash.sha256',
    "ipv4-addr:value": "ip.address"
}


@click.command()
@click.argument('filenames', nargs=-1, type=click.Path())
@click.option('-t', '--tree_view', is_flag=True)
@click.option('-e', '--es_host')
@click.option('-u', '--es_username')
@click.option('-p', '--es_password')
def read_json(
    filenames: List,
    tree_view: bool,
    es_host:str = None,
    es_username:str = None,
    es_password:str = None):
    """Read stix from files."""
    console=Console()
    
    if es_host:
        if es_username:
            if not es_password:
                es_password = click.prompt('Enter password', hide_input=True)
            es = Elasticsearch(es_host, http_auth=(es_username, es_password))
        else:
            es = Elasticsearch(es_host)

        info = es.info()
        print(f"Connected to {es_host}, version {info['version']['number']}")
    else:
        es = None

    for filename in filenames:
        malwares = dict()
        indicators = dict()
        relations = list()

        table = Table(title=filename)
        tree = Tree(filename)

        with open(filename) as fd:
            stixes = orjson.loads(fd.read())['objects']
        
        for stix in stixes:
            if stix['type'] == 'malware':
                malware = Malware(**stix)
                malwares[malware.id] = malware

            if stix['type'] == 'indicator':
                patterns = dict()
                stix['pattern'] = stix.get('pattern','').strip('[]')
                for pattern in stix['pattern'].split(' '):
                    if '=' in pattern:
                        key, value = pattern.split('=')
                        key = pattern_fields[key]
                        patterns[key] = value.strip("'")
                stix['patterns'] = patterns

                indicator = Indicator(**stix)
                indicators[indicator.id] = indicator
            
            if stix['type'] == 'relationship':
                source = stix['source_ref']
                target = stix['target_ref']
                relations.append((source, target))

        for source, target in relations:
            if source in indicators and target in malwares:
                source_indicator = indicators[source]
                target_malware = malwares[target]

                target_malware.indicators.append(source_indicator)
                source_indicator.indicates = target_malware

        if es:
            upload = list()
            for indicator in indicators.values():
                upload.append(indicator.to_es())
            bulk(es, upload)


        if tree_view:
            for malware in malwares.values():
                malware_tree = tree.add(malware.name)
                for indicator in malware.indicators:
                    for key, value in indicator.patterns.items():
                        malware_tree.add(f"{key}={value}")

            console.print(tree)

if __name__=='__main__':
    read_json()

