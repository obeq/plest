# Plest - quick and dirty graylisting of files

## Getting started

Before you begin, start by prepapring nsrllookup. This commando will take a while.

```bash
docker-compose -f settings/svr/docker-compose-prepare.yml up svr-prepare && 
docker-compose -f settings/svr/docker-compose-prepare.yml rm -fsv
```

To download and start all services, do:

```bash
docker-compose up
```

This will bring everything up. Note that the Plaso container does not have a proper run command, so it will immediately stop. It's only in the docker-compose definition in order to be downloaded.

Also note that it takes a while for the nsrllookup service to start.

To set the passwords for the Elasticsearch cluster, run:

```bash
docker exec -it plaso-es ./bin/elasticsearch-setup-passwords interactive
```

Then change the password in ```settings/kibana/kibana.yml``` to the appropriate password. Restart the Kibana container:

```bash
docker-compose restart kibana
```

## Running Plaso

Extract data, including hashes, from `testdata/evidences/`.
```bash
docker run -v ${pwd}/testdata/:/data log2timeline/plaso log2timeline --hashers all /data/evidences.plaso /data/evidences
```

Enrich the data with data from nsrlsvr.
```bash
docker run --network plest_default -v ${pwd}/testdata/:/data log2timeline/plaso psort --analysis nsrlsvr --nsrlsvr-hash md5 --nsrlsvr-host svr --nsrlsvr-port 9120 -o null /data/evidences.plaso
```

Send the data to Elasticsearch.
```bash
docker run --network=plest_default -v ${pwd}/testdata:/data -v ${pwd}/settings/plaso/elasticsearch.mappings:/home/plaso/data/elasticsearch.mappings log2timeline/plaso psort -o elastic --server elasticsearch --index_name psort /data/evidences.plaso
```

Write the data to timeline.log. Use `-o elasticsearch` to output data to Elasticsearch instead.
```bash
docker run -v ${pwd}/testdata/:/data log2timeline/plaso psort -w /data/timeline.log /data/evidences.plaso
```

To drop into a shell at the Plaso container, run:
```bash
docker run -v ./testdata/:/data --entrypoint=/bin/bash --network plest_default -it log2timeline/plaso
```

## NSRLlookup

NSRLlookup is based on [nsrllookup](https://github.com/cybagard/nsrllookup) by cybagard.

Copyright (c) 2020 cybagard