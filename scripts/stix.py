import click
from rich import print
from rich.console import Console
from rich.table import Table
from rich.tree import Tree
import orjson
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime


class Malware(BaseModel):
    id: str
    name: Optional[str]
    created: datetime


class Indicator(BaseModel):
    id: str
    patterns: Dict[str,str]
    indicates: Optional[Malware]


@click.command()
@click.argument('filenames', nargs=-1, type=click.Path())
def read_json(filenames):
    """Read stix from files."""
    console=Console()
    
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
                        patterns[key] = value
                stix['patterns'] = patterns

                indicator = Indicator(**stix)
                indicators[indicator.id] = indicator
            
            if stix['type'] == 'relationship':
                source_type, source = stix['source_ref'].split('--')
                target_type, target = stix['target_ref'].split('--')
                relations.append((source, target))

        for source, target in relations:
            if source in indicators and target in malwares:
                indicators[source].indicates = malwares.target
                print(indicators[source])
            
        # console.print(indicators)

    



if __name__=='__main__':
    read_json()

