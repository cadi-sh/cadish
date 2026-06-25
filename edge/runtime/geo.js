// geo.js — the edge is the single source of truth for geo (design §2.8).
//
// Cloudflare resolves the client's geo into `request.cf`; we read it and (a) feed
// the interpreter's geo fields so {geo}/{geo.continent}/{geo.region} and the `geo`
// matcher resolve at the edge, and (b) inject the SAME values as headers on the
// origin request so the Cadish server behind resolves geo identically (it has no
// request.cf). No I/O.

// resolveGeo reads request.cf into the interpreter's geo classes. Country and
// continent are upper-cased 2-letter codes; region is composed as COUNTRY-SUBDIV
// (e.g. "US-UT") from cf.country + cf.regionCode, matching the {geo.region}
// convention. Missing fields resolve to "" (the interpreter treats "" as "no
// geo" — a `geo` matcher never matches an empty class).
export function resolveGeo(request) {
  const cf = (request && request.cf) || {};
  const country = up(cf.country);
  const continent = up(cf.continent);
  const subdivision = up(cf.regionCode || "");
  let region = "";
  if (country && subdivision) region = country + "-" + subdivision;
  return { geo: country, geoContinent: continent, geoRegion: region };
}

function up(v) {
  return v ? String(v).toUpperCase() : "";
}

// GEO_HEADERS are the header names the edge injects so the server behind sees the
// edge-resolved geo. They mirror the conventional CDN country header plus two
// cadish-specific headers for the finer granularities; a cadish server geo source
// can be pointed at these. Keep in sync with the server's geo header config.
export const GEO_HEADERS = {
  country: "CF-IPCountry",
  continent: "X-Cadish-Geo-Continent",
  region: "X-Cadish-Geo-Region",
};

// applyGeoHeaders sets the resolved geo onto a Headers object (the origin request
// headers), so the Cadish server behind classifies the request the same way. Only
// non-empty classes are written.
export function applyGeoHeaders(headers, geo) {
  if (geo.geo) headers.set(GEO_HEADERS.country, geo.geo);
  if (geo.geoContinent) headers.set(GEO_HEADERS.continent, geo.geoContinent);
  if (geo.geoRegion) headers.set(GEO_HEADERS.region, geo.geoRegion);
}
