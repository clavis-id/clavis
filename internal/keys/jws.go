package keys

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"uuid"

	"github.com/go-jose/go-jose/v4"
)

// ErrInvalidToken reports a token that is not a compact JWS signed by one of
// the tenant's published keys with the expected type.
var ErrInvalidToken = errors.New("keys: invalid token")

// Sign signs payload as a compact JWS (RFC 7515, section 7.1) with the
// tenant's current key for alg. The header carries the key ID and typ.
func (m *Manager) Sign(ctx context.Context, tenantID uuid.UUID, alg, typ string, payload []byte) (string, error) {
	s, err := m.Signer(ctx, tenantID, alg)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.SignatureAlgorithm(alg), Key: jose.JSONWebKey{Key: s.Key, KeyID: s.KeyID}},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)),
	)
	if err != nil {
		return "", fmt.Errorf("keys: preparing to sign with %s: %w", alg, err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("keys: signing with %s: %w", alg, err)
	}
	token, err := obj.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("keys: serializing a signature: %w", err)
	}
	return token, nil
}

// Verify checks that token is a compact JWS signed with one of the tenant's
// published keys, using an algorithm of the policy, and that its typ header
// names the media type typ, with or without the "application/" prefix (RFC
// 7515, section 4.1.9). It returns the payload. Every failure other than a
// store error wraps ErrInvalidToken.
func (m *Manager) Verify(ctx context.Context, tenantID uuid.UUID, token, typ string) ([]byte, error) {
	algorithms := make([]jose.SignatureAlgorithm, len(m.policy.Algorithms))
	for i, alg := range m.policy.Algorithms {
		algorithms[i] = jose.SignatureAlgorithm(alg)
	}
	obj, err := jose.ParseSigned(token, algorithms)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if len(obj.Signatures) != 1 {
		return nil, fmt.Errorf("%w: the token has %d signatures", ErrInvalidToken, len(obj.Signatures))
	}
	header := obj.Signatures[0].Header
	got, _ := header.ExtraHeaders[jose.HeaderType].(string)
	if !strings.EqualFold(strings.TrimPrefix(strings.ToLower(got), "application/"), typ) {
		return nil, fmt.Errorf("%w: the token type is not %s", ErrInvalidToken, typ)
	}
	set, err := m.JWKS(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, k := range set.Key(header.KeyID) {
		if k.Algorithm != header.Algorithm {
			continue
		}
		payload, err := obj.Verify(k.Key)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
		}
		return payload, nil
	}
	return nil, fmt.Errorf("%w: no published key matches the token", ErrInvalidToken)
}
