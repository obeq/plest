# Plest - quick and dirty graylisting of files

## Getting started

To download and start all services, do:

```docker-compose up```

This will bring everything up. Note that the Plaso container does not have a proper run command, so it will immediately stop. It's only in the docker-compose definition in order to be downloaded.

To set the passwords for the Elasticsearch cluster, run:

```docker exec -it plaso-es ./bin/elasticsearch-setup-passwords interactive```

Then change the password in ```settings/kibana/kibana.yml``` to the appropriate password. Restart the Kibana container:

```docker-compose restart kibana```