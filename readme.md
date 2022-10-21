# Threat scan as a standalone script

## Why not make it a part of Kibana?

It was faster to try different options here, as altering anything on kibana side takes some time - services need to restart etc...

## What it does currently

This goes through threat list, matching it with the events on Elasticsearch. Matched log entries are marked
with a timestamp and a threat id, preparing them for further processing.

See `index.ts` for configuration. This is intended to run locally, unless the connection logic is changed.

Execute with `npm start` and observe the awesomeness.
