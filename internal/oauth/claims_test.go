package oauth

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseClaimsRequest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  ClaimsRequest
	}{
		{"empty object", `{}`, ClaimsRequest{}},
		{"empty targets", `{"userinfo":{},"id_token":null}`, ClaimsRequest{}},
		{
			"both targets",
			`{"userinfo":{"given_name":{"essential":true},"nickname":null,"email":{"essential":false}},
			  "id_token":{"auth_time":{"essential":true},"acr":{"values":["urn:a","urn:b"]}}}`,
			ClaimsRequest{
				UserInfo: map[string]ClaimRequest{
					"given_name": {Essential: true},
					"nickname":   {},
					"email":      {},
				},
				IDToken: map[string]ClaimRequest{
					"auth_time": {Essential: true},
					"acr":       {ValueRequested: true, Values: []string{"urn:a", "urn:b"}},
				},
			},
		},
		{
			"value and values together, keeping only strings",
			`{"id_token":{"acr":{"value":"urn:a","values":["urn:b",1,null,{"x":"y"}]},"age":{"value":18}}}`,
			ClaimsRequest{IDToken: map[string]ClaimRequest{
				"acr": {ValueRequested: true, Values: []string{"urn:a", "urn:b"}},
				"age": {ValueRequested: true},
			}},
		},
		{
			"null value and empty values request no value",
			`{"id_token":{"sub":{"value":null},"acr":{"values":[]}}}`,
			ClaimsRequest{IDToken: map[string]ClaimRequest{"sub": {}, "acr": {}}},
		},
		{
			"unknown members and claims are kept for the caller to ignore",
			`{"other":{"x":1},"userinfo":{"unknown_claim":{"purpose":"testing","essential":true}}}`,
			ClaimsRequest{UserInfo: map[string]ClaimRequest{"unknown_claim": {Essential: true}}},
		},
	}
	for _, tt := range tests {
		got, err := ParseClaimsRequest(tt.input)
		if err != nil {
			t.Errorf("%s: ParseClaimsRequest() unexpected error: %v", tt.name, err)
			continue
		}
		if diff := cmp.Diff(tt.want, got); diff != "" {
			t.Errorf("%s: ParseClaimsRequest() mismatch (-want +got):\n%s", tt.name, diff)
		}
	}

	for _, input := range []string{
		``,
		`null`,
		`"claims"`,
		`[]`,
		`{"userinfo":[]}`,
		`{"userinfo":{"name":true}}`,
		`{"userinfo":{"name":{"essential":"yes"}}}`,
		`{"id_token":{"acr":{"values":"urn:a"}}}`,
		`{"userinfo":{"name":null,"name":null}}`,
		`{"userinfo":{}} {}`,
		`{"userinfo":{"name":null}`,
	} {
		if got, err := ParseClaimsRequest(input); err == nil {
			t.Errorf("ParseClaimsRequest(%q) = %+v, want an error", input, got)
		}
	}
}

// FuzzParseClaimsRequest checks that parsing never panics and that an
// accepted request keeps only string values.
func FuzzParseClaimsRequest(f *testing.F) {
	for _, seed := range []string{
		`{}`,
		`{"userinfo":{"name":{"essential":true}}}`,
		`{"id_token":{"acr":{"value":"a","values":["b",2]}}}`,
		`{"userinfo":null,"id_token":{"email":null}}`,
		`[1]`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		r, err := ParseClaimsRequest(input)
		if err != nil {
			if r.UserInfo != nil || r.IDToken != nil {
				t.Errorf("ParseClaimsRequest(%q) returned claims with an error", input)
			}
			return
		}
		for _, target := range []map[string]ClaimRequest{r.UserInfo, r.IDToken} {
			if target != nil && len(target) == 0 {
				t.Errorf("ParseClaimsRequest(%q) returned an empty, non-nil map", input)
			}
		}
	})
}
