package storetest

import (
	"errors"
	"testing"
	"time"
	"uuid"

	"github.com/google/go-cmp/cmp"

	"clavisid.org/clavis/store"
)

func runBrandings(t *testing.T, open OpenFunc) {
	newStore := func(t *testing.T) (store.Store, store.Tenant) {
		t.Helper()
		s := open(t)
		tn := newTenant("acme")
		mustCreate(t, s.Tenants(), tn)
		return s, tn
	}
	radius := 12
	theme := store.Theme{
		Light:  store.ThemeColors{Accent: "#0b5cad", AccentText: "#ffffff", Background: "#f4f5f7"},
		Dark:   store.ThemeColors{Accent: "#4493f8", Text: "#e6edf3"},
		Radius: &radius,
	}
	logo := store.Logo{ContentType: "image/png", Data: []byte("\x89PNG\r\n\x1a\nlogo"), Hash: "a1b2c3"}
	at := time.Date(2026, 10, 20, 12, 0, 0, 123456789, time.UTC)

	t.Run("ThemeAndLogo", func(t *testing.T) {
		t.Parallel()
		s, tn := newStore(t)
		b := s.Brandings()
		if err := b.PutTheme(t.Context(), tn.ID, theme, at); err != nil {
			t.Fatalf("PutTheme() unexpected error: %v", err)
		}
		want := store.Branding{TenantID: tn.ID, Theme: theme, UpdatedAt: at.Truncate(time.Microsecond)}
		if got, err := b.Get(t.Context(), tn.ID); err != nil || !cmp.Equal(want, got) {
			t.Fatalf("Get() after PutTheme() = %+v, %v; want %+v", got, err, want)
		}
		if _, err := b.GetLogo(t.Context(), tn.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetLogo() without a logo = %v, want ErrNotFound", err)
		}

		// PutLogo keeps the theme, and PutTheme keeps the logo.
		if err := b.PutLogo(t.Context(), tn.ID, logo, at.Add(time.Minute)); err != nil {
			t.Fatalf("PutLogo() unexpected error: %v", err)
		}
		if got, err := b.GetLogo(t.Context(), tn.ID); err != nil || !cmp.Equal(logo, got) {
			t.Errorf("GetLogo() = %+v, %v; want %+v", got, err, logo)
		}
		other := store.Theme{Light: store.ThemeColors{Accent: "#123456"}}
		if err := b.PutTheme(t.Context(), tn.ID, other, at.Add(2*time.Minute)); err != nil {
			t.Fatalf("PutTheme() unexpected error: %v", err)
		}
		want = store.Branding{TenantID: tn.ID, Theme: other, LogoType: logo.ContentType, LogoHash: logo.Hash,
			UpdatedAt: at.Add(2 * time.Minute).Truncate(time.Microsecond)}
		if got, err := b.Get(t.Context(), tn.ID); err != nil || !cmp.Equal(want, got) {
			t.Errorf("Get() = %+v, %v; want %+v", got, err, want)
		}

		// DeleteLogo keeps the theme and succeeds once.
		if err := b.DeleteLogo(t.Context(), tn.ID, at.Add(3*time.Minute)); err != nil {
			t.Fatalf("DeleteLogo() unexpected error: %v", err)
		}
		want = store.Branding{TenantID: tn.ID, Theme: other, UpdatedAt: at.Add(3 * time.Minute).Truncate(time.Microsecond)}
		if got, err := b.Get(t.Context(), tn.ID); err != nil || !cmp.Equal(want, got) {
			t.Errorf("Get() after DeleteLogo() = %+v, %v; want %+v", got, err, want)
		}
		if _, err := b.GetLogo(t.Context(), tn.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetLogo() after DeleteLogo() = %v, want ErrNotFound", err)
		}
		if err := b.DeleteLogo(t.Context(), tn.ID, at); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a second DeleteLogo() = %v, want ErrNotFound", err)
		}

		if err := b.Delete(t.Context(), tn.ID); err != nil {
			t.Fatalf("Delete() unexpected error: %v", err)
		}
		if _, err := b.Get(t.Context(), tn.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() after Delete() = %v, want ErrNotFound", err)
		}
		if err := b.Delete(t.Context(), tn.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a second Delete() = %v, want ErrNotFound", err)
		}
	})

	t.Run("LogoWithoutTheme", func(t *testing.T) {
		t.Parallel()
		s, tn := newStore(t)
		b := s.Brandings()
		if err := b.PutLogo(t.Context(), tn.ID, logo, at); err != nil {
			t.Fatalf("PutLogo() unexpected error: %v", err)
		}
		want := store.Branding{TenantID: tn.ID, LogoType: logo.ContentType, LogoHash: logo.Hash,
			UpdatedAt: at.Truncate(time.Microsecond)}
		if got, err := b.Get(t.Context(), tn.ID); err != nil || !cmp.Equal(want, got) {
			t.Errorf("Get() = %+v, %v; want %+v", got, err, want)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		t.Parallel()
		s, tn := newStore(t)
		b := s.Brandings()
		if _, err := b.Get(t.Context(), tn.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() = %v, want ErrNotFound", err)
		}
		if _, err := b.GetLogo(t.Context(), tn.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("GetLogo() = %v, want ErrNotFound", err)
		}
		if err := b.DeleteLogo(t.Context(), tn.ID, at); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("DeleteLogo() = %v, want ErrNotFound", err)
		}
		if err := b.Delete(t.Context(), tn.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Delete() = %v, want ErrNotFound", err)
		}
	})

	t.Run("UnknownTenant", func(t *testing.T) {
		t.Parallel()
		b := open(t).Brandings()
		if err := b.PutTheme(t.Context(), uuid.NewV7(), theme, at); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("PutTheme() for an unknown tenant = %v, want ErrNotFound", err)
		}
		if err := b.PutLogo(t.Context(), uuid.NewV7(), logo, at); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("PutLogo() for an unknown tenant = %v, want ErrNotFound", err)
		}
	})

	t.Run("TenantIsolationAndDeletion", func(t *testing.T) {
		t.Parallel()
		s, tn := newStore(t)
		other := newTenant("other")
		mustCreate(t, s.Tenants(), other)
		b := s.Brandings()
		if err := b.PutTheme(t.Context(), tn.ID, theme, at); err != nil {
			t.Fatalf("PutTheme() unexpected error: %v", err)
		}
		if err := b.PutLogo(t.Context(), tn.ID, logo, at); err != nil {
			t.Fatalf("PutLogo() unexpected error: %v", err)
		}
		if _, err := b.Get(t.Context(), other.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() for another tenant = %v, want ErrNotFound", err)
		}
		if err := s.Tenants().Delete(t.Context(), tn.ID); err != nil {
			t.Fatalf("deleting the tenant: %v", err)
		}
		if _, err := b.Get(t.Context(), tn.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Get() after the tenant was deleted = %v, want ErrNotFound", err)
		}
	})
}
