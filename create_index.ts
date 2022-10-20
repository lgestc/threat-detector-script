import { Client } from "@elastic/elasticsearch";

export const createIndex = async (
  es: Client,
  index: string,
  properties: any = {}
) =>
  es.indices.create({
    index,
    mappings: {
      properties,
    },
  });
