import { Client } from "@elastic/elasticsearch";
import { chunk } from "lodash";
import { parseInterval, scan } from "./scan";

const EVENTS_INDEX = "benchmark-events";
const THREATS_INDEX = "benchmark-threats";

const client = new Client({
  auth: {
    username: "elastic",
    password: "changeme",
  },
  node: "http://localhost:9200",
});

// How many threat processing tasks should be running at any given time
const CONCURRENCY = 8;

interface PrepareFixturesOptions {
  threats: number;
  events: number;
}

interface Scenario extends PrepareFixturesOptions {
  interval: "10s" | "30s" | "1m" | "5m" | "10m";
  // how many runs are we going to do (with specified interval)
  runs: number;
}

const newThreats = async (threats: number) => {
  for (const threatChunk of chunk(Array(threats), 1000)) {
    await client.bulk({
      operations: threatChunk.flatMap(() => [
        {
          index: {
            _index: THREATS_INDEX,
          },
        },
        {
          "@timestamp": new Date().toISOString(),
          threat: {
            indicator: {
              type: "url",
              first_seen: new Date().toISOString(),
              url: {
                full: `http://url${Math.floor(Math.random() * threats)}.com`,
              },
              ip: "127.0.0.1",
              marking: {
                tlp: "RED",
              },
            },
            feed: {
              name: `fakebeat_${Math.floor(Math.random() * threats)}`,
            },
          },
          event: {
            type: "indicator",
            category: "threat",
            dataset: "ti_*",
            kind: "enrichment",
          },
        },
      ]),
      refresh: true,
    });
  }
};

const newEvents = async (events: number) => {
  for (const eventsChunk of chunk(Array(events), 1000)) {
    await client.bulk({
      operations: eventsChunk.flatMap(() => [
        {
          index: {
            _index: EVENTS_INDEX,
          },
        },
        {
          "@timestamp": new Date().toISOString(),

          url: {
            full: `http://url${Math.floor(Math.random() * events)}.com`,
          },

          source: {
            ip: `${Math.floor(Math.random() * 255)}.${Math.floor(
              Math.random() * 255
            )}.${Math.floor(Math.random() * 255)}.${Math.floor(
              Math.random() * 255
            )}`,
          },
        },
      ]),
      refresh: true,
    });
  }
};

const appendFixtures = async ({ threats, events }: PrepareFixturesOptions) => {
  const threatsToAppend = threats;
  const eventsToAppend = events;

  console.log(
    `appending ${threatsToAppend} threats and ${eventsToAppend} events`
  );

  await newThreats(threatsToAppend);
  await newEvents(eventsToAppend);
};

const threatsPendingFirstScan = async () =>
  (
    await client.count({
      index: THREATS_INDEX,
      query: {
        bool: {
          must_not: {
            exists: {
              field: "threat.detection.last_scan",
            },
          },
        },
      },
    })
  ).count;

const resetFixtures = async ({ threats, events }: PrepareFixturesOptions) => {
  // cleanup
  try {
    await client.indices.delete({
      index: [EVENTS_INDEX, THREATS_INDEX],
    });
  } catch (e: unknown) {
    if (e instanceof Error) {
      console.warn(e.message);
    }
  }

  await client.indices.create({
    index: THREATS_INDEX,
    mappings: {
      properties: {
        "@timestamp": { type: "date" },

        threat: {
          properties: {
            indicator: {
              properties: {
                type: { type: "keyword" },
                ip: { type: "ip" },
                first_seen: { type: "date" },
                url: {
                  properties: {
                    full: { type: "keyword" },
                  },
                },
                marking: {
                  properties: {
                    tlp: { type: "keyword" },
                  },
                },
              },
            },
            feed: {
              properties: {
                name: {
                  type: "keyword",
                },
              },
            },
          },
        },

        event: {
          properties: {
            type: { type: "keyword" },
            category: { type: "keyword" },
            dataset: { type: "keyword" },
            kind: { type: "keyword" },
          },
        },
      },
    },
  });

  await client.indices.create({
    index: EVENTS_INDEX,
    mappings: {
      properties: {
        "@timestamp": { type: "date" },

        url: {
          properties: {
            full: { type: "keyword" },
          },
        },

        source: {
          properties: {
            ip: { type: "ip" },
          },
        },
      },
    },
  });

  console.log(`preparing test data`);

  await newThreats(threats);
  await newEvents(events);
};

const wait = async (ms: number) =>
  new Promise((resolve) => setTimeout(resolve, ms));

const entry = async () => {
  const scenarios: Scenario[] = [
    {
      threats: 10,
      events: 100,
      interval: "10s",
      runs: 10,
    },
    {
      threats: 1000,
      events: 100_000,
      interval: "10s",
      runs: 5,
    },
    {
      threats: 10_000,
      events: 100_000,
      interval: "30s",
      runs: 10,
    },
    {
      threats: 100_000,
      events: 1_000_000,
      interval: "5m",
      runs: 10,
    },
  ];

  for (const scenario of scenarios) {
    let executedTimes = 0;

    console.log(
      `scenario: ${scenario.threats} threats ${scenario.events} events`
    );

    await resetFixtures(scenario);

    while (executedTimes < scenario.runs) {
      executedTimes++;

      console.log(`run ${executedTimes}/${scenario.runs}`);

      const delaySeconds = parseInterval(scenario.interval);
      console.log(`should run ${delaySeconds}s`);

      // do not wait for completion here as we want to test the overlap as well
      scan(
        { client, log: console.log },
        {
          eventsIndex: [EVENTS_INDEX],
          threatIndex: [THREATS_INDEX],
          concurrency: CONCURRENCY,
          verbose: false,
          interval: scenario.interval,
        }
      );

      await wait(delaySeconds * 1000 + 1000);

      console.log(`unscanned: ${await threatsPendingFirstScan()}`);

      if (executedTimes < scenario.runs) {
        await appendFixtures(scenario);
      }
    }

    console.log(`!!! unscanned total: ${await threatsPendingFirstScan()}`);

    console.log("\n\n");
  }
};

entry();
