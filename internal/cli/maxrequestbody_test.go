package cli

import "testing"

func TestParseMaxRequestBodyFlag(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"", 0, false},    // default: unlimited
		{"0", 0, false},   // explicit unlimited
		{" 0 ", 0, false}, // trimmed
		{"25MiB", 25 << 20, false},
		{"1.5GiB", 1610612736, false},
		{"500KB", 500_000, false},
		{"-5MiB", 0, true},  // negative is rejected
		{"banana", 0, true}, // unparseable
	}
	for _, c := range cases {
		got, err := parseMaxRequestBodyFlag(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseMaxRequestBodyFlag(%q): want error, got nil (val %d)", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseMaxRequestBodyFlag(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseMaxRequestBodyFlag(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
