import { Threat } from "./threat";

/**
 * Returns filter clause with 'match' conditions for relevant fields only
 * @param threat
 * @returns
 */
export const shouldClauseForThreat = (threat: Threat) => {
  switch (threat["threat.indicator.type"]) {
    case "url": {
      return [
        {
          match: {
            "url.full": threat["threat.indicator.url.full"],
          },
        },
      ];
    }

    case "file": {
      return [
        {
          match: {
            "file.hash.md5": threat["threat.indicator.file.hash.md5"],
            "file.hash.sha1": threat["threat.indicator.file.hash.sha1"],
          },
        },
      ];
    }
  }
};
