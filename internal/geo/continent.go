package geo

import "strings"

// Continent maps an ISO 3166-1 alpha-2 country code to a 2-letter continent code
// (one of AF, AN, AS, EU, NA, OC, SA), or Unknown for an unrecognized/blank code.
// The country is upper-cased before lookup so a lower-case CDN header value (the
// header source already upper-cases, but a CIDR table or test may not) resolves.
//
// This is the {geo.continent} granularity: it lets a site express the
// "EU → EUR else USD" currency split (and any continent-scoped policy) WITHOUT a
// GeoIP database — the continent is a pure, deterministic function of the country
// code cadish already resolves. The mapping is a small in-tree static table (D11:
// no GeoIP dependency); it is built once and read-only, so lookups are
// allocation-free and safe for concurrent use.
func Continent(country string) string {
	if country == "" {
		return Unknown
	}
	c, ok := countryContinent[strings.ToUpper(country)]
	if !ok {
		return Unknown
	}
	return c
}

// continentCodes is the bounded set of continent classes Continent can emit. It is
// used by tooling (cadish check) to confirm {geo.continent} is low-cardinality.
var continentCodes = []string{"AF", "AN", "AS", "EU", "NA", "OC", "SA"}

// ContinentCodes returns the bounded set of continent codes {geo.continent} can
// emit (plus Unknown is implicit). A copy is returned so callers cannot mutate the
// table.
func ContinentCodes() []string {
	return append([]string(nil), continentCodes...)
}

// countryContinent is the static ISO 3166-1 alpha-2 country → continent table.
// Continent codes: AF=Africa, AN=Antarctica, AS=Asia, EU=Europe, NA=North America
// (incl. Central America + Caribbean), OC=Oceania, SA=South America. This is a
// data table only — no logic — and deliberately in-tree so cadish needs no GeoIP
// dependency (D11). It is the standard ISO-region grouping; ambiguous/transcontinental
// countries (RU, TR, etc.) follow the common GeoIP convention noted inline.
var countryContinent = map[string]string{
	// Africa
	"DZ": "AF", "AO": "AF", "BJ": "AF", "BW": "AF", "BF": "AF", "BI": "AF",
	"CM": "AF", "CV": "AF", "CF": "AF", "TD": "AF", "KM": "AF", "CG": "AF",
	"CD": "AF", "CI": "AF", "DJ": "AF", "EG": "AF", "GQ": "AF", "ER": "AF",
	"SZ": "AF", "ET": "AF", "GA": "AF", "GM": "AF", "GH": "AF", "GN": "AF",
	"GW": "AF", "KE": "AF", "LS": "AF", "LR": "AF", "LY": "AF", "MG": "AF",
	"MW": "AF", "ML": "AF", "MR": "AF", "MU": "AF", "YT": "AF", "MA": "AF",
	"MZ": "AF", "NA": "AF", "NE": "AF", "NG": "AF", "RE": "AF", "RW": "AF",
	"SH": "AF", "ST": "AF", "SN": "AF", "SC": "AF", "SL": "AF", "SO": "AF",
	"ZA": "AF", "SS": "AF", "SD": "AF", "TZ": "AF", "TG": "AF", "TN": "AF",
	"UG": "AF", "EH": "AF", "ZM": "AF", "ZW": "AF",

	// Antarctica
	"AQ": "AN", "BV": "AN", "GS": "AN", "TF": "AN", "HM": "AN",

	// Asia
	"AF": "AS", "AM": "AS", "AZ": "AS", "BH": "AS", "BD": "AS", "BT": "AS",
	"BN": "AS", "KH": "AS", "CN": "AS", "GE": "AS", "HK": "AS",
	"IN": "AS", "ID": "AS", "IR": "AS", "IQ": "AS", "IL": "AS", "JP": "AS",
	"JO": "AS", "KZ": "AS", "KW": "AS", "KG": "AS", "LA": "AS", "LB": "AS",
	"MO": "AS", "MY": "AS", "MV": "AS", "MN": "AS", "MM": "AS", "NP": "AS",
	"KP": "AS", "OM": "AS", "PK": "AS", "PS": "AS", "PH": "AS", "QA": "AS",
	"SA": "AS", "SG": "AS", "KR": "AS", "LK": "AS", "SY": "AS", "TW": "AS",
	"TJ": "AS", "TH": "AS", "TL": "AS", "TR": "AS", // Turkey: ISO/GeoIP groups under Asia
	"TM": "AS", "AE": "AS", "UZ": "AS", "VN": "AS", "YE": "AS",

	// Europe
	"AL": "EU", "AD": "EU", "AT": "EU", "BY": "EU", "BE": "EU", "BA": "EU",
	"BG": "EU", "HR": "EU", "CY": "EU", // Cyprus: EU member (Eurozone) — grouped EU for the EU→EUR mapping
	"CZ": "EU", "DK": "EU", "EE": "EU", "FO": "EU",
	"FI": "EU", "FR": "EU", "DE": "EU", "GI": "EU", "GR": "EU", "GG": "EU",
	"HU": "EU", "IS": "EU", "IE": "EU", "IM": "EU", "IT": "EU", "JE": "EU",
	"XK": "EU", "LV": "EU", "LI": "EU", "LT": "EU", "LU": "EU", "MT": "EU",
	"MD": "EU", "MC": "EU", "ME": "EU", "NL": "EU", "MK": "EU", "NO": "EU",
	"PL": "EU", "PT": "EU", "RO": "EU", "RU": "EU", // Russia: ISO/GeoIP convention groups under Europe
	"SM": "EU", "RS": "EU", "SK": "EU", "SI": "EU", "ES": "EU", "SE": "EU",
	"CH": "EU", "UA": "EU", "GB": "EU", "VA": "EU", "AX": "EU", "SJ": "EU",

	// North America (incl. Central America + Caribbean)
	"AI": "NA", "AG": "NA", "AW": "NA", "BS": "NA", "BB": "NA", "BZ": "NA",
	"BM": "NA", "BQ": "NA", "CA": "NA", "KY": "NA", "CR": "NA", "CU": "NA",
	"CW": "NA", "DM": "NA", "DO": "NA", "SV": "NA", "GL": "NA", "GD": "NA",
	"GP": "NA", "GT": "NA", "HT": "NA", "HN": "NA", "JM": "NA", "MQ": "NA",
	"MX": "NA", "MS": "NA", "NI": "NA", "PA": "NA", "PR": "NA", "BL": "NA",
	"KN": "NA", "LC": "NA", "MF": "NA", "PM": "NA", "VC": "NA", "SX": "NA",
	"TT": "NA", "TC": "NA", "US": "NA", "VG": "NA", "VI": "NA",

	// Oceania
	"AS": "OC", "AU": "OC", "CK": "OC", "FJ": "OC", "PF": "OC", "GU": "OC",
	"KI": "OC", "MH": "OC", "FM": "OC", "NR": "OC", "NC": "OC", "NZ": "OC",
	"NU": "OC", "NF": "OC", "MP": "OC", "PW": "OC", "PG": "OC", "PN": "OC",
	"WS": "OC", "SB": "OC", "TK": "OC", "TO": "OC", "TV": "OC", "UM": "OC",
	"VU": "OC", "WF": "OC",

	// South America
	"AR": "SA", "BO": "SA", "BR": "SA", "CL": "SA", "CO": "SA", "EC": "SA",
	"FK": "SA", "GF": "SA", "GY": "SA", "PY": "SA", "PE": "SA", "SR": "SA",
	"UY": "SA", "VE": "SA",
}
