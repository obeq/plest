import click
from rich import print
from rich.console import Console
from rich.table import Table
from rich.tree import Tree
import json

@click.command()
@click.argument('filenames', nargs=-1, type=click.Path())
def read_json(filenames):
    """Read stix from files."""
    console=Console()
    
    for filename in filenames:
        table = Table(title=filename)
        tree = Tree(filename)

        with open(filename) as fd:
            stixes = json.load(fd)['objects']
        
        for stix in stixes[:100]:
            stix_tree = tree.add(stix.get('name', 'unnamed'))
            for key in stix:
                stix_tree.add(f"{key}: {stix[key]}")

        console.print(tree)

    



if __name__=='__main__':
    read_json()

