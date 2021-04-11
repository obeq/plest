# Plest - quick and dirty graylisting of files

## Getting started

Before you begin, start by prepapring nsrllookup:

```bash
docker-compose -f settings/svr/docker-compose-prepare.yml up svr-prepare && 
docker-compose -f settings/svr/docker-compose-prepare.yml rm -fsv
```

To download and start all services, do:

```bash
docker-compose up
```

This will bring everything up. Note that the Plaso container does not have a proper run command, so it will immediately stop. It's only in the docker-compose definition in order to be downloaded.

To set the passwords for the Elasticsearch cluster, run:

```bash
docker exec -it plaso-es ./bin/elasticsearch-setup-passwords interactive
```

Then change the password in ```settings/kibana/kibana.yml``` to the appropriate password. Restart the Kibana container:

```bash
docker-compose restart kibana
```

## NSRLlookup

NSRLlookup is based on [nsrllookup](https://github.com/cybagard/nsrllookup) by cybagard.

Copyright (c) 2020 cybagard