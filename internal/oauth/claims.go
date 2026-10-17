package oauth

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
)

// ClaimsRequest is the claims parameter of an authorization request: the
// claims a client asks for individually, for the userinfo response and for
// the ID token (OpenID Connect Core 1.0, section 5.5). The maps are keyed by
// claim name and are nil when the request names no claims for that target.
type ClaimsRequest struct {
	UserInfo map[string]ClaimRequest
	IDToken  map[string]ClaimRequest
}

// ClaimRequest describes how a client asks for one claim (OpenID Connect
// Core 1.0, section 5.5.1).
type ClaimRequest struct {
	Essential bool
	// Values holds the string values of the value and values members.
	// Values of other JSON types are left out.
	Values []string
}

// claimsRequestJSON is the JSON form of the claims parameter. Members other
// than userinfo and id_token are ignored, as section 5.5 allows.
type claimsRequestJSON struct {
	UserInfo map[string]*claimRequestJSON `json:"userinfo"`
	IDToken  map[string]*claimRequestJSON `json:"id_token"`
}

type claimRequestJSON struct {
	Essential bool             `json:"essential"`
	Value     jsontext.Value   `json:"value"`
	Values    []jsontext.Value `json:"values"`
}

// ParseClaimsRequest parses the value of a claims parameter. A claim may be
// requested with null, which asks for it with the default behavior.
func ParseClaimsRequest(s string) (ClaimsRequest, error) {
	var raw claimsRequestJSON
	// The value must be a JSON object; json.Unmarshal into a struct accepts
	// null, which is not one.
	if v := jsontext.Value(s); v.Kind() != '{' {
		return ClaimsRequest{}, errors.New("oauth: the claims parameter is not a JSON object")
	}
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		return ClaimsRequest{}, fmt.Errorf("oauth: parsing the claims parameter: %w", err)
	}
	return ClaimsRequest{UserInfo: claimRequests(raw.UserInfo), IDToken: claimRequests(raw.IDToken)}, nil
}

func claimRequests(raw map[string]*claimRequestJSON) map[string]ClaimRequest {
	if len(raw) == 0 {
		return nil
	}
	requests := make(map[string]ClaimRequest, len(raw))
	for name, r := range raw {
		var c ClaimRequest
		if r != nil {
			c.Essential = r.Essential
			for _, v := range append([]jsontext.Value{r.Value}, r.Values...) {
				var s string
				if v.Kind() == '"' && json.Unmarshal(v, &s) == nil {
					c.Values = append(c.Values, s)
				}
			}
		}
		requests[name] = c
	}
	return requests
}
