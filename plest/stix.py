import click
from rich import print
from rich.console import Console
from rich.table import Table
from rich.tree import Tree
from rich.traceback import install
from rich.progress import track
import orjson
from pydantic import BaseModel
from typing import Optional, List, Dict, TextIO
from datetime import datetime
from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk
from glob import glob
from itertools import chain
import asyncio

console = Console()
install(show_locals=False)  # Installs rich as exception traceback printer. Makes errors look prettier...


class Malware(BaseModel):
    id: str
    name: Optional[str]
#    created: datetime

#    indicators: Optional[List] = []


class Indicator(BaseModel):
    id: str
    patterns: Dict[str, str]

    indicates: Optional[Malware]

    def to_es(self, index: str) -> Dict:
        obj = dict()
        obj['_id'] = self.id
        obj['_index'] = index

        source = dict()
        source['id'] = self.id
        if self.indicates:
            source['indicates'] = self.indicates.dict()

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
    "ipv4-addr:value": "ip.address",
    "artifact:hashes.MD5": 'hash.md5',
    "artifact:hashes.'SHA-1'": 'hash.sha1',
    "artifact:hashes.'SHA-256'": 'hash.sha256',
    "email-addr": "user.email",                             # There's a RFC proposal that gives better support for these fields in ECS.
    "email-message": "labels.email-message",                # There's not really any support for this in ECS.
    "windows-registry-key": "registry.path",                # Assumption. This is for values such as HKLM\SOFTWARE\Microsoft...
                                                                # That is, including the hive name and the actual key.
}


class StixReader():
    """Reads stix from json files and returns ES ready indicators."""

    def __init__(self, index: str = 'indicators'):
        self.index = index

        self.malwares = dict()
        self.indicators = dict()
        self.missing_patterns = set()

    async def stix_converter(self, stixes: List[Dict]):
        """Converts stix dicts to ES ready indicators."""

        for stix in stixes:
            if stix['type'] == 'malware':
                malware = Malware(**stix)
                self.malwares[malware.id] = malware

            if stix['type'] == 'indicator':
                patterns = dict()
                stix['pattern'] = stix.get('pattern', '').strip('[]')
                for pattern in stix['pattern'].split(' '):
                    if '=' in pattern:
                        key, value = pattern.split('=', 1)
                        if key not in pattern_fields:
                            # console.log(f"No pattern defined for '{key}', skipping.")
                            self.missing_patterns.add(key)
                            continue

                        key = pattern_fields[key]
                        patterns[key] = value.strip("'")
                stix['patterns'] = patterns

                indicator = Indicator(**stix)
                self.indicators[indicator.id] = indicator

            if stix['type'] == 'relationship':
                source = stix['source_ref']
                target = stix['target_ref']

                if source in self.indicators and target in self.malwares:
                    indicator = self.indicators.pop(source)
                    malware = self.malwares.get(target)

                    indicator.indicates = malware

                    yield indicator.to_es(self.index)

    async def flush_unmatched(self):
        """Returns the indicators that haven't been matched to any malware (hopefully none)."""

        for indicator in self.indicators.values():
            yield indicator.to_es(self.index)


async def read_json(
        filenames: List[str],
        es: AsyncElasticsearch,
        index_name: str = 'indicators',
    ):
    """Reads stixes from jsons and posts them to Elasticsearch."""

    info = await es.info()
    console.log(
        f"Connected to Elasticsearch, version {info['version']['number']}.")

    if await es.indices.exists(index=index_name):
        console.log(f"Index {index_name} already exists, skipping template load.")
    else:
        console.log(f"Uploading index templates...")
        template = {
            "index_patterns": [
                index_name
            ],
            "composed_of": [
                "logs-mappings",
                "logs-settings"
            ]
        }
        await es.indices.put_index_template(name=index_name, body=template)

    reader = StixReader(index_name)
    uploads = 0
    for filename in track(filenames, "Reading files..."):
        # console.log(f"Reading from {filename}.")
        with open(filename) as fd:
            try:
                stixes = orjson.loads(fd.read())['objects']
            except orjson.JSONDecodeError:
                console.log(f"JSONDecodeError while reading {filename}.")
                continue

            successful, errors = await async_bulk(es, reader.stix_converter(stixes))
            uploads += successful
            # console.log(f"{successful} stixes imported successfully.")

    console.log(f"{uploads} stixes uploaded successfully.")
    if reader.missing_patterns:
        console.log(f"These patterns were missing: {reader.missing_patterns}.")

    console.log(
        f"After importing, {len(reader.indicators)} indicators haven't been matched.")

    console.log(f"Flushing...")
    successful, errors = await async_bulk(es, reader.flush_unmatched())
    console.log(f"{successful} indicators imported successfully.")

    await es.close()


@click.command()
@click.argument('filenames', nargs=-1, type=click.Path())
@click.option('-e', '--es_host')
@click.option('-u', '--es_username')
@click.option('-p', '--es_password')
@click.option('--index_name', default='indicators')
def main(
        filenames: List,
        es_host: str = None,
        es_username: str = None,
        es_password: str = None,
        index_name: str = 'indicators',
    ):
    """Read stix from files."""

    console.log("Stixreader starting...")

    filenames = [glob(filename) for filename in filenames]
    filenames = list(chain(*filenames))

    if es_host:
        console.log("Connecting to Elasticsearch...")
        if es_username:
            if not es_password:
                es_password = click.prompt('Enter password', hide_input=True)
            es = AsyncElasticsearch(
                es_host, http_auth=(es_username, es_password))
        else:
            es = AsyncElasticsearch(es_host)

        asyncio.run(read_json(filenames, es, index_name))

    else:
        es = None

        # console.print(tree)


if __name__ == '__main__':
    main(auto_envvar_prefix='STIX')
