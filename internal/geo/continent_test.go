package geo

import "testing"

// TestContinent: country code → continent via the in-tree static table.
func TestContinent(t *testing.T) {
	cases := map[string]string{
		"US": "NA", // United States
		"CA": "NA", // Canada
		"ES": "EU", // Spain
		"FR": "EU", // France
		"DE": "EU", // Germany
		"GB": "EU", // United Kingdom
		"BR": "SA", // Brazil
		"AR": "SA", // Argentina
		"JP": "AS", // Japan
		"CN": "AS", // China
		"AU": "OC", // Australia
		"NG": "AF", // Nigeria
		"ZA": "AF", // South Africa
		"AQ": "AN", // Antarctica
		"us": "NA", // lower-case is upper-cased before lookup
	}
	for cc, want := range cases {
		if got := Continent(cc); got != want {
			t.Errorf("Continent(%q) = %q, want %q", cc, got, want)
		}
	}
}

// TestContinentUnknown: an unknown / blank / sentinel country yields Unknown.
func TestContinentUnknown(t *testing.T) {
	for _, cc := range []string{"", "ZZ", "unknown", Unknown, "XX"} {
		if got := Continent(cc); got != Unknown {
			t.Errorf("Continent(%q) = %q, want %q", cc, got, Unknown)
		}
	}
}

// TestContinentCoversEUExamples: the EU countries the age gate / EUR mapping care
// about all resolve to EU.
func TestContinentCoversEUExamples(t *testing.T) {
	eu := []string{
		"AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR",
		"HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK",
		"SI", "ES", "SE",
	}
	for _, cc := range eu {
		if got := Continent(cc); got != "EU" {
			t.Errorf("Continent(%q) = %q, want EU", cc, got)
		}
	}
}
