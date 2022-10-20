import { Client } from "@elastic/elasticsearch";

/**
 * Store (upsert) matches
 */
export const upsert = async (
  es: Client,
  index: string,
  docs: any[],
  getId: (doc: any) => string
) =>
  es.bulk({
    operations: docs.flatMap((doc) => [
      {
        index: {
          _index: index,
          _id: getId(doc),
        },
      },
      doc,
    ]),
  });
