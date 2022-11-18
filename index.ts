import { Client } from "@elastic/elasticsearch";
import { scan } from "./scan";

const EVENTS_INDEX = "filebeat-url";
const THREATS_INDEX = "logs-ti_*";

const client = new Client({
  auth: {
    username: "elastic",
    password: "changeme",
  },
  node: "http://localhost:9200",
});

// How many threat processing tasks should be running at any given time
const CONCURRENCY = 4;

const entry = async () => {
  await scan(
    { client, log: console.log },
    {
      eventsIndex: EVENTS_INDEX,
      threatIndex: THREATS_INDEX,
      concurrency: CONCURRENCY,
    }
  );
};

entry();
