package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kdlbs/kandev/pluginsdk"
)

type memSecrets struct {
	mu     sync.Mutex
	values map[string]string
	setErr error
}

func newMemSecrets() *memSecrets { return &memSecrets{values: map[string]string{}} }

func (m *memSecrets) GetSecret(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.values[key]
	return v, ok, nil
}

func (m *memSecrets) SetSecret(ctx context.Context, key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.setErr != nil {
		return m.setErr
	}
	m.values[key] = value
	return nil
}

func (m *memSecrets) put(t *testing.T, p rotatingPair) {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	m.values[rotationSecretPrefix+p.Seed] = string(raw)
}

func (m *memSecrets) stored(t *testing.T) rotatingPair {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	var p rotatingPair
	if err := json.Unmarshal([]byte(m.values[rotationSecretPrefix+rotationSeed("xoxe-1-seed")]), &p); err != nil {
		t.Fatalf("stored pair unreadable: %v", err)
	}
	return p
}

// rotationSlack fakes oauth.v2.access with single-use refresh tokens, like
// Slack, and apps.connections.open accepting only the newest access token.
type rotationSlack struct {
	mu         sync.Mutex
	valid      map[string]bool // live refresh tokens
	access     string          // the access token Slack currently accepts
	issued     int
	refreshes  int
	refreshErr string
	rateLimit  bool
	// accessKind replaces the issued access token's prefix, to model a
	// refresh token that belongs to another token kind.
	accessKind string
	// onRefresh runs while a refresh request is being answered.
	onRefresh func()
	// socketURL is what apps.connections.open returns; a URL the dialer
	// rejects at once keeps Run cycling without any network.
	socketURL string
	// onOpen sees the token of each apps.connections.open call.
	onOpen func(token string)
	// refreshGate, when set, holds each refresh before it is answered,
	// without blocking other endpoints.
	refreshGate chan struct{}
	// refreshArrived, when set, is signalled as a refresh reaches the gate.
	refreshArrived chan struct{}
	// emptyAccess answers a refresh with no access token.
	emptyAccess bool
	// rawAccess, when set, is the raw JSON sent as access_token.
	rawAccess string
	// extraFields is spliced into a successful refresh response.
	extraFields string
	// rejectOpen makes apps.connections.open refuse every token.
	rejectOpen bool
	// truncate cuts a successful refresh response right after the
	// refresh token, before the object closes: "clean" ends the body there,
	// "short" also declares a longer Content-Length, so reading the body
	// fails with io.ErrUnexpectedEOF, as for a dropped connection.
	truncate string
	// tokenType replaces the token_type of a successful refresh, which is
	// app_level by default, as Slack documents for app-level tokens.
	tokenType string
	// lostReplies is how many refreshes Slack carries out, without
	// invalidating the redeemed token yet, while the answer is lost.
	lostReplies int
	// lostAs is how a lost answer arrives: a dropped connection by default,
	// "502" for a gateway error, "internal_error" for that Slack error.
	lostAs string
}

func newRotationSlack(t *testing.T, refresh string) *rotationSlack {
	t.Helper()
	s := &rotationSlack{valid: map[string]bool{refresh: true}}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.URL.Path == "/oauth.v2.access" && s.refreshGate != nil {
			if s.refreshArrived != nil {
				s.refreshArrived <- struct{}{}
			}
			<-s.refreshGate
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		switch r.URL.Path {
		case "/oauth.v2.access":
			s.refreshes++
			if s.onRefresh != nil {
				s.onRefresh()
			}
			if s.rateLimit {
				w.Header().Set("Retry-After", "120")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			if r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("client_id") != testClientID || r.PostForm.Get("client_secret") != "csecret" {
				fmt.Fprint(w, `{"ok":false,"error":"bad_client_secret"}`)
				return
			}
			if s.refreshErr != "" {
				fmt.Fprintf(w, `{"ok":false,"error":%q}`, s.refreshErr)
				return
			}
			old := r.PostForm.Get("refresh_token")
			if !s.valid[old] {
				fmt.Fprint(w, `{"ok":false,"error":"invalid_refresh_token"}`)
				return
			}
			lost := s.lostReplies > 0
			if lost {
				// Slack carried out the exchange but its answer is lost;
				// the redeemed token still works within the grace period.
				s.lostReplies--
			} else {
				delete(s.valid, old)
			}
			s.issued++
			kind := "xoxe.xapp-"
			if s.accessKind != "" {
				kind = s.accessKind
			}
			s.access = fmt.Sprintf("%s1-access%d", kind, s.issued)
			next := fmt.Sprintf("xoxe-1-refresh%d", s.issued)
			s.valid[next] = true
			access := strconv.Quote(s.access)
			if s.emptyAccess {
				access = `""`
			}
			if s.rawAccess != "" {
				access = s.rawAccess
			}
			tokenType := "app_level"
			if s.tokenType != "" {
				tokenType = s.tokenType
			}
			if lost {
				switch s.lostAs {
				case "502":
					w.WriteHeader(http.StatusBadGateway)
				case "internal_error":
					fmt.Fprint(w, `{"ok":false,"error":"internal_error"}`)
				default:
					w.Header().Set(lostReplyHeader, "1")
				}
				return
			}
			// Slack's documented field order puts the refresh token last.
			body := fmt.Sprintf(`{"ok":true,%s"access_token":%s,"token_type":%q,"expires_in":43200,"refresh_token":%q`, s.extraFields, access, tokenType, next)
			if s.truncate == "" {
				body += "}"
			}
			if s.truncate == "short" {
				w.Header().Set(shortBodyHeader, "1")
			}
			fmt.Fprint(w, body)
		case "/apps.connections.open":
			if s.onOpen != nil {
				s.onOpen(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			}
			if s.rejectOpen || r.Header.Get("Authorization") != "Bearer "+s.access {
				fmt.Fprint(w, `{"ok":false,"error":"token_expired"}`)
				return
			}
			url := s.socketURL
			if url == "" {
				url = "wss://example.invalid/socket"
			}
			fmt.Fprintf(w, `{"ok":true,"url":%q}`, url)
		default:
			http.NotFound(w, r)
		}
	})
	// Served in-process through the default transport, which every client
	// in this package uses, so the stub needs no socket.
	prevTransport, prevBase := http.DefaultTransport, slackAPIBase
	http.DefaultTransport = handlerTransport{handler}
	slackAPIBase = "http://slack.test"
	t.Cleanup(func() { http.DefaultTransport, slackAPIBase = prevTransport, prevBase })
	return s
}

type handlerTransport struct{ h http.Handler }

// shortBodyHeader makes handlerTransport end the body with
// io.ErrUnexpectedEOF instead of io.EOF.
const shortBodyHeader = "X-Test-Short-Body"

// lostReplyHeader makes handlerTransport fail as if the connection dropped
// after Slack processed the request.
const lostReplyHeader = "X-Test-Lost-Reply"

type shortBody struct{ io.Reader }

func (b shortBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, r)
	// Like a real transport, a request cancelled while in flight fails.
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	resp := rec.Result()
	if resp.Header.Get(lostReplyHeader) != "" {
		return nil, errors.New("connection reset by peer")
	}
	if resp.Header.Get(shortBodyHeader) != "" {
		resp.Body = io.NopCloser(shortBody{resp.Body})
	}
	return resp, nil
}

func (s *rotationSlack) refreshCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshes
}

func rotatingConfig(access, refresh string) *config {
	return &config{Mode: authModeApp, AppToken: access, BotToken: "xoxb-1", AppRefreshToken: refresh, ClientID: testClientID, ClientSecret: "csecret"}
}

// testClientID is shaped like a Slack Client ID.
const testClientID = "1234567890.987654321"

func pastedSource(store secretStore) *appTokenSource {
	return newAppTokenSource(rotatingConfig("xoxe.xapp-pasted", "xoxe-1-seed"), store)
}

// mustToken runs a renewal pass, as the worker does, and then asks for a
// token; with rejected set it reports a rejection instead.
func mustToken(t *testing.T, src *appTokenSource, rejected, code string) string {
	t.Helper()
	if rejected == "" {
		src.Renew(context.Background())
	}
	got, err := src.Token(context.Background(), rejected, code)
	if err != nil {
		t.Fatalf("Token(%q, %q): %v", rejected, code, err)
	}
	return got
}

func TestStaticAppTokenIsReturnedAsIs(t *testing.T) {
	src := newAppTokenSource(&config{AppToken: "xapp-1-static"}, nil)
	got, err := src.Token(context.Background(), "xapp-1-static", "invalid_auth")
	if err != nil || got != "xapp-1-static" || src.Rotating() {
		t.Fatalf("Token = %q, %v, rotating=%v; want the static token untouched", got, err, src.Rotating())
	}
}

func TestPastedTokenIsExchangedAtStartAndPersistedAsOnePair(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	l := &socketListener{tokens: pastedSource(store)}
	if url, err := l.openConnection(context.Background()); err != nil || url == "" {
		t.Fatalf("openConnection = %q, %v", url, err)
	}
	pair := store.stored(t)
	if pair.Access != "xoxe.xapp-1-access1" || pair.Refresh != "xoxe-1-refresh1" || pair.ExpiresAt.IsZero() {
		t.Fatalf("stored pair = %+v, want the exchanged access+refresh with Slack's expiry", pair)
	}
	if slack.refreshCount() != 1 {
		t.Fatalf("refreshes = %d, want exactly 1", slack.refreshCount())
	}
}

func TestRejectedStoredTokenIsRefreshedAndRetried(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	// The stored pair is a live successor of the seed, so only the proof
	// can let Slack's token_expired trigger a refresh.
	slack.valid = map[string]bool{"xoxe-1-live": true}
	store.put(t, rotatingPair{Access: "xoxe.xapp-stale", Refresh: "xoxe-1-live", ExpiresAt: time.Now().Add(time.Hour), Seed: rotationSeed("xoxe-1-seed"), Retries: maxForcedRefreshes})
	store.values[proofSecretPrefix+rotationSeed("xoxe-1-seed")] = tokenDigest("xoxe.xapp-stale")
	var firstTry string
	slack.onOpen = func(token string) {
		if firstTry == "" {
			firstTry = token
		}
	}
	l := &socketListener{tokens: newAppTokenSource(rotatingConfig("xoxe.xapp-pasted", "xoxe-1-seed"), store)}
	if _, err := l.openConnection(context.Background()); err != nil {
		t.Fatalf("openConnection: %v; Slack's token_expired must trigger one refresh and a retry", err)
	}
	if firstTry != "xoxe.xapp-stale" {
		t.Fatalf("first attempt used %q, want the stored access token", firstTry)
	}
	if slack.refreshCount() != 1 || store.stored(t).Access != "xoxe.xapp-1-access1" {
		t.Fatalf("refreshes = %d, stored = %+v", slack.refreshCount(), store.stored(t))
	}
}

func TestRestartResumesFromStoredPairNotSpentConfigToken(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	mustToken(t, pastedSource(store), "", "")

	restarted := pastedSource(store)
	if got := mustToken(t, restarted, "", ""); got != "xoxe.xapp-1-access1" {
		t.Fatalf("Token after restart = %q, want the stored access token", got)
	}
	restarted.now = func() time.Time { return time.Now().Add(13 * time.Hour) }
	if got := mustToken(t, restarted, "", ""); got != "xoxe.xapp-1-access2" {
		t.Fatalf("renewal after restart = %q; the stored refresh token must be used", got)
	}
	if slack.refreshCount() != 2 {
		t.Fatalf("refreshes = %d, want 2", slack.refreshCount())
	}
}

func TestNewlyPastedPairReplacesStoredChain(t *testing.T) {
	newRotationSlack(t, "xoxe-1-other")
	store := newMemSecrets()
	store.put(t, rotatingPair{Access: "xoxe.xapp-old", Refresh: "xoxe-1-old", ExpiresAt: time.Now().Add(time.Hour), Seed: rotationSeed("xoxe-1-previous")})
	src := newAppTokenSource(rotatingConfig("xoxe.xapp-new", "xoxe-1-other"), store)
	if got := mustToken(t, src, "", ""); got != "xoxe.xapp-1-access1" {
		t.Fatalf("Token = %q; the newly configured refresh token must start the chain", got)
	}
}

func TestStaticTokenWinsOverStoredRotatingChain(t *testing.T) {
	store := newMemSecrets()
	store.put(t, rotatingPair{Access: "xoxe.xapp-old", Refresh: "xoxe-1-seed", Seed: rotationSeed("xoxe-1-seed")})
	src := newAppTokenSource(rotatingConfig("xapp-1-new-app", "xoxe-1-seed"), store)
	if got := mustToken(t, src, "", ""); got != "xapp-1-new-app" {
		t.Fatalf("Token = %q; a pasted xapp- token must replace the rotating chain", got)
	}
}

func TestTokenIsRenewedBeforeExpiry(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	src := pastedSource(newMemSecrets())
	now := time.Now()
	src.now = func() time.Time { return now }
	mustToken(t, src, "", "")
	mustToken(t, src, "", "")
	if slack.refreshCount() != 1 {
		t.Fatalf("a fresh token was renewed again (refreshes=%d)", slack.refreshCount())
	}
	now = now.Add(12*time.Hour - refreshMargin + time.Second)
	if got := mustToken(t, src, "", ""); got != "xoxe.xapp-1-access2" {
		t.Fatalf("Token near expiry = %q, want a renewed token", got)
	}
}

func TestEarlyRenewalFailureKeepsValidToken(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	src := pastedSource(newMemSecrets())
	now := time.Now()
	src.now = func() time.Time { return now }
	mustToken(t, src, "", "")
	slack.mu.Lock()
	slack.refreshErr = "service_unavailable"
	slack.mu.Unlock()
	now = now.Add(12*time.Hour - refreshMargin/2)
	if got := mustToken(t, src, "", ""); got != "xoxe.xapp-1-access1" {
		t.Fatalf("Token = %q; an unexpired token must stay in use when early renewal fails", got)
	}
}

func TestFailedSaveIsRetriedAndReported(t *testing.T) {
	store := newMemSecrets()
	slack := newRotationSlack(t, "xoxe-1-seed")
	// The vault fails only once Slack has spent the refresh token.
	slack.onRefresh = func() { store.mu.Lock(); store.setErr = errors.New("vault down"); store.mu.Unlock() }
	src := pastedSource(store)
	if got := mustToken(t, src, "", ""); got != "xoxe.xapp-1-access1" {
		t.Fatalf("Token = %q; the spent refresh token leaves the new pair as the only working one", got)
	}
	if !strings.Contains(src.Warning(), "could not be saved") {
		t.Fatalf("Warning = %q, want the unsaved pair reported", src.Warning())
	}
	store.setErr = nil
	mustToken(t, src, "", "")
	if p := store.stored(t); p.Refresh != "xoxe-1-refresh1" || src.Warning() != "" {
		t.Fatalf("stored refresh = %q, warning = %q; want the save retried and the warning cleared", p.Refresh, src.Warning())
	}
}

func TestSpentRefreshTokenIsTriedOnce(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.refreshErr = "invalid_refresh_token"
	src := pastedSource(newMemSecrets())
	for range 3 {
		if got := mustToken(t, src, "", ""); got != "xoxe.xapp-pasted" {
			t.Fatalf("Token = %q; the pasted token stays usable until Slack rejects it", got)
		}
	}
	if !strings.Contains(src.Warning(), "already used") {
		t.Fatalf("Warning = %q, want the renewal failure reported", src.Warning())
	}
	if _, err := src.Token(context.Background(), "xoxe.xapp-pasted", "token_expired"); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("err = %v, want the spent refresh token named once the pasted token is rejected", err)
	}
	if slack.refreshCount() != 1 {
		t.Fatalf("refreshes = %d, want 1: a spent refresh token stays spent", slack.refreshCount())
	}
}

func TestRejectedFreshTokenStopsRefreshing(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	src := pastedSource(newMemSecrets())
	fresh := mustToken(t, src, "", "")
	// One token_expired for a token that never opened a socket buys one
	// more refresh; after that, nothing more is spent.
	retried := mustToken(t, src, fresh, "token_expired")
	for _, code := range []string{"token_expired", "invalid_auth", "token_expired"} {
		if _, err := src.Token(context.Background(), retried, code); err == nil {
			t.Fatal("want the refused replacement reported")
		}
	}
	if slack.refreshCount() != 2 {
		t.Fatalf("refreshes = %d; tokens Slack issues and then rejects must not keep burning refresh tokens", slack.refreshCount())
	}
}

func TestRejectedUnexpiredProvenTokenGetsOneRefresh(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	src := pastedSource(newMemSecrets())
	tok := mustToken(t, src, "", "")
	src.Confirm(tok)
	replacement := mustToken(t, src, tok, "invalid_auth")
	for range 2 {
		if _, err := src.Token(context.Background(), replacement, "invalid_auth"); err == nil || !strings.Contains(err.Error(), "not expired") {
			t.Fatalf("err = %v, want the rejected-token diagnosis once the replacement is refused too", err)
		}
	}
	if slack.refreshCount() != 2 {
		t.Fatalf("refreshes = %d, want exactly one forced refresh", slack.refreshCount())
	}
}

func TestBadRefreshTokenIsTerminal(t *testing.T) {
	var final *terminalRefreshError
	if err := refreshFailure("bad_refresh_token"); !errors.As(err, &final) {
		t.Fatalf("refreshFailure(bad_refresh_token) = %v, want a terminal error", err)
	}
}

func TestLeftoverRefreshTokenDoesNotBlockSessionFallback(t *testing.T) {
	mode, err := detectMode(&config{AppRefreshToken: "xoxe-1-x", SessionToken: "xoxc-1", SessionCookie: "d"})
	if err != nil || mode != authModeSession {
		t.Fatalf("detectMode = %v, %v; a complete session pair must win over an orphaned refresh token", mode, err)
	}
}

func TestTokenExpiredIsRefreshedDespiteLocalExpiry(t *testing.T) {
	newRotationSlack(t, "xoxe-1-seed")
	src := pastedSource(newMemSecrets())
	tok := mustToken(t, src, "", "")
	src.Confirm(tok)
	if got := mustToken(t, src, tok, "token_expired"); got != "xoxe.xapp-1-access2" {
		t.Fatalf("Token = %q; Slack's token_expired must win over the local expiry estimate", got)
	}
}

func TestLateRejectionOfReplacedTokenKeepsNewToken(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	src := pastedSource(newMemSecrets())
	now := time.Now()
	src.now = func() time.Time { return now }
	old := mustToken(t, src, "", "")
	src.Confirm(old)
	now = now.Add(12 * time.Hour)
	renewed := mustToken(t, src, "", "")
	if got := mustToken(t, src, old, "invalid_auth"); got != renewed {
		t.Fatalf("Token = %q, want the renewed token %q untouched by a late rejection", got, renewed)
	}
	if slack.refreshCount() != 2 {
		t.Fatalf("refreshes = %d, want 2", slack.refreshCount())
	}
}

func TestRefreshTokenOfAnotherKindIsNotStored(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.accessKind = "xoxe.xoxb-"
	store := newMemSecrets()
	src := pastedSource(store)
	mustToken(t, src, "", "")
	if !strings.Contains(src.Warning(), "bot token") {
		t.Fatalf("Warning = %q, want it to name the bot token", src.Warning())
	}
	if got := store.stored(t).Access; got != "xoxe.xapp-pasted" {
		t.Fatalf("Socket Mode slot holds %q; a non-app token pair must never be stored there", got)
	}
	var kept rotatingPair
	if err := json.Unmarshal([]byte(store.values[foreignSecretPrefix+rotationSeed("xoxe-1-seed")]), &kept); err != nil || kept.Refresh != "xoxe-1-refresh1" {
		t.Fatalf("kept = %+v, %v; Slack spent the pasted token, so its successor must be kept", kept, err)
	}
}

func TestUnrecognizedRefreshErrorIsNotEchoed(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.refreshErr = "boom xoxe-1-leaked-secret"
	_, err := refreshAppToken(context.Background(), testClientID, "csecret", "xoxe-1-seed")
	if err == nil || strings.Contains(err.Error(), "leaked") {
		t.Fatalf("err = %v, want a generic message without the response text", err)
	}
}

func TestRateLimitedRefreshWaitsForRetryAfter(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.rateLimit = true
	src := pastedSource(newMemSecrets())
	for range 3 {
		if got := mustToken(t, src, "", ""); got != "xoxe.xapp-pasted" {
			t.Fatalf("Token = %q; the pasted token stays in use while rate limited", got)
		}
	}
	if slack.refreshCount() != 1 {
		t.Fatalf("refreshes = %d, want Retry-After honoured", slack.refreshCount())
	}
}

func TestStoppedListenerStartsNoExchange(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	src := pastedSource(newMemSecrets())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = src.Token(ctx, "", "")
	if slack.refreshCount() != 0 {
		t.Fatalf("refreshes = %d; a stopped listener must not spend a refresh token", slack.refreshCount())
	}
}

func TestExchangeInFlightSurvivesCancellation(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	src := pastedSource(store)
	ctx, cancel := context.WithCancel(context.Background())
	slack.onRefresh = cancel
	src.Renew(ctx)
	if got, err := src.Token(context.Background(), "", ""); err != nil || got != "xoxe.xapp-1-access1" {
		t.Fatalf("Token = %q, %v; an exchange Slack already answered must complete", got, err)
	}
	if p := store.stored(t); p.Refresh != "xoxe-1-refresh1" {
		t.Fatalf("stored refresh = %q, want the new pair saved despite cancellation", p.Refresh)
	}
}

func TestStaticTokenRejectionIsNotRefreshed(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	l := &socketListener{tokens: newAppTokenSource(&config{AppToken: "xapp-1-bad"}, nil)}
	_, err := l.openConnection(context.Background())
	if err == nil || !strings.Contains(err.Error(), "token_expired") || slack.refreshCount() != 0 {
		t.Fatalf("err = %v, refreshes = %d; want the plain rejection, no refresh", err, slack.refreshCount())
	}
}

func TestValidateRotationFields(t *testing.T) {
	base := func() *config { return rotatingConfig("xoxe.xapp-1-a", "xoxe-1-b") }
	cases := []struct {
		name    string
		mutate  func(*config)
		wantErr string
	}{
		{"complete rotating set", func(*config) {}, ""},
		{"static token alone", func(c *config) { c.AppToken, c.AppRefreshToken, c.ClientID, c.ClientSecret = "xapp-1", "", "", "" }, ""},
		{"static token ignores leftover rotation fields", func(c *config) { c.AppToken, c.ClientSecret = "xapp-1", "" }, ""},
		{"rotating bot token", func(c *config) { c.BotToken = "xoxe.xoxb-1-x" }, "bot token rotates"},
		{"refresh token alone bootstraps", func(c *config) { c.AppToken = "" }, ""},
		{"rotating token without refresh", func(c *config) { c.AppRefreshToken = "" }, "refresh token"},
		{"refresh token in wrong shape", func(c *config) { c.AppRefreshToken = "xapp-1" }, "must start with \"xoxe-\""},
		{"missing client secret", func(c *config) { c.ClientSecret = "" }, "Client Secret"},
		{"refresh pasted as access", func(c *config) { c.AppToken = "xoxe-1-x" }, "refresh token, not an access token"},
		{"client secret in the client ID field", func(c *config) { c.ClientID = "0123456789abcdef0123456789abcdef" }, "regenerate the Client Secret"},
		{"refresh token in the client ID field", func(c *config) { c.ClientID = "xoxe-1-x" }, "revoke or regenerate"},
		{"bot token in the client ID field", func(c *config) { c.ClientID = "xoxb-1-x" }, "revoke or regenerate"},
		{"access token in the client ID field", func(c *config) { c.ClientID = "xoxe.xapp-1-x" }, "revoke or regenerate"},
		{"client ID in the wrong shape", func(c *config) { c.ClientID = "A0123" }, "dotted number"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(c)
			err := c.validateApp()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateApp() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validateApp() = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestExpiredTokenIsNotOfferedWhileRenewalIsBlocked(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	src := pastedSource(newMemSecrets())
	now := time.Now()
	src.now = func() time.Time { return now }
	mustToken(t, src, "", "")
	slack.mu.Lock()
	slack.rateLimit = true
	slack.mu.Unlock()
	now = now.Add(13 * time.Hour)
	for range 2 {
		if got, err := src.Token(context.Background(), "", ""); err == nil || !(strings.Contains(err.Error(), "rate limit") || strings.Contains(err.Error(), "paused")) {
			t.Fatalf("Token = %q, %v; an expired token must not be offered while renewal waits", got, err)
		}
	}
	if slack.refreshCount() != 2 {
		t.Fatalf("refreshes = %d, want one blocked renewal attempt", slack.refreshCount())
	}
}

func TestRestartKeepsGuardForUnprovenToken(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	src := pastedSource(store)
	fresh := mustToken(t, src, "", "")
	retried := mustToken(t, src, fresh, "token_expired")
	restarted := pastedSource(store)
	if _, err := restarted.Token(context.Background(), retried, "token_expired"); err == nil || !strings.Contains(err.Error(), "as well") {
		t.Fatalf("err = %v; a restart must not reset the retry budget of a token that never opened a socket", err)
	}
	if slack.refreshCount() != 2 {
		t.Fatalf("refreshes = %d, want 2", slack.refreshCount())
	}
}

func TestProofIsStoredForRestart(t *testing.T) {
	newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	src := pastedSource(store)
	tok := mustToken(t, src, "", "")
	src.Confirm(tok)
	src.SaveProof(context.Background())
	if store.values[proofSecretPrefix+rotationSeed("xoxe-1-seed")] != tokenDigest(tok) {
		t.Fatal("a token that opened a socket must be stored as proven")
	}
	restarted := pastedSource(store)
	if got := mustToken(t, restarted, tok, "token_expired"); got != "xoxe.xapp-1-access2" {
		t.Fatalf("Token = %q; a proven token Slack calls expired must be refreshed after a restart", got)
	}
}

func TestHexShapedRefreshErrorIsNotEchoed(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.refreshErr = "0123456789abcdef0123456789abcdef"
	_, err := refreshAppToken(context.Background(), testClientID, "csecret", "xoxe-1-seed")
	if err == nil || strings.Contains(err.Error(), "0123456789abcdef") {
		t.Fatalf("err = %v, want unlisted codes withheld", err)
	}
}

func TestRefreshTokenAloneSelectsAppMode(t *testing.T) {
	_, err := loadConfig(map[string]any{"app_refresh_token": "xoxe-1-x", "client_id": testClientID, "client_secret": "cs", "utility_agent": "a"})
	if err == nil || !strings.Contains(err.Error(), "bot token") {
		t.Fatalf("loadConfig = %v, want app mode asking for the bot token", err)
	}
}

func TestTransientRenewalFailureIsReported(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	src := pastedSource(newMemSecrets())
	now := time.Now()
	src.now = func() time.Time { return now }
	mustToken(t, src, "", "")
	slack.mu.Lock()
	slack.refreshErr = "service_unavailable"
	slack.mu.Unlock()
	now = now.Add(12*time.Hour - refreshMargin/2)
	mustToken(t, src, "", "")
	if !strings.Contains(src.Warning(), "service_unavailable") {
		t.Fatalf("Warning = %q, want the failing renewal reported", src.Warning())
	}
	slack.mu.Lock()
	slack.refreshErr = ""
	slack.mu.Unlock()
	now = now.Add(refreshCooldown + time.Second)
	mustToken(t, src, "", "")
	if src.Warning() != "" {
		t.Fatalf("Warning = %q, want it cleared by a successful renewal", src.Warning())
	}
}

func TestRefreshDoesNotFollowRedirects(t *testing.T) {
	var followed bool
	prevTransport, prevBase := http.DefaultTransport, slackAPIBase
	http.DefaultTransport = handlerTransport{http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host == "elsewhere.test" {
			followed = true
		}
		http.Redirect(w, r, "http://elsewhere.test/steal", http.StatusTemporaryRedirect)
	})}
	slackAPIBase = "http://slack.test"
	t.Cleanup(func() { http.DefaultTransport, slackAPIBase = prevTransport, prevBase })
	_, err := refreshAppToken(context.Background(), testClientID, "csecret", "xoxe-1-seed")
	if err == nil || followed {
		t.Fatalf("err = %v, followed = %v; the refresh body must never be replayed to a redirect target", err, followed)
	}
}

func TestFailedForcedRefreshKeepsRetryingCurrentToken(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	src := pastedSource(newMemSecrets())
	tok := mustToken(t, src, "", "")
	src.Confirm(tok)
	mustToken(t, src, "", "")
	slack.mu.Lock()
	slack.refreshErr = "invalid_refresh_token"
	slack.mu.Unlock()
	if _, err := src.Token(context.Background(), tok, "invalid_auth"); err == nil {
		t.Fatal("want the refresh failure reported")
	}
	if got := mustToken(t, src, "", ""); got != tok {
		t.Fatalf("Token = %q; an unexpired token Slack may accept again must stay in use", got)
	}
}

func TestJSONRateLimitHonoursRetryAfter(t *testing.T) {
	prevTransport, prevBase := http.DefaultTransport, slackAPIBase
	http.DefaultTransport = handlerTransport{http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "90")
		fmt.Fprint(w, `{"ok":false,"error":"ratelimited"}`)
	})}
	slackAPIBase = "http://slack.test"
	t.Cleanup(func() { http.DefaultTransport, slackAPIBase = prevTransport, prevBase })
	_, err := refreshAppToken(context.Background(), testClientID, "csecret", "xoxe-1-seed")
	var limited *rateLimitedError
	if !errors.As(err, &limited) || limited.after != 90*time.Second {
		t.Fatalf("err = %v, want a 90s rate limit", err)
	}
}

func TestRenewalWorkerRenewsWhileConnected(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	src := pastedSource(store)
	now := time.Now()
	var nowMu sync.Mutex
	src.now = func() time.Time { nowMu.Lock(); defer nowMu.Unlock(); return now }
	mustToken(t, src, "", "")
	nowMu.Lock()
	now = now.Add(12 * time.Hour)
	nowMu.Unlock()

	l := &socketListener{tokens: src, renewNow: make(chan struct{}, 1), renewEvery: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); l.renew(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for slack.refreshCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if slack.refreshCount() != 2 || store.stored(t).Access != "xoxe.xapp-1-access2" {
		t.Fatalf("refreshes = %d, stored = %+v; the worker must renew and save without a reconnect", slack.refreshCount(), store.stored(t))
	}
}

func TestProofIsNotCreditedToReplacement(t *testing.T) {
	newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	src := pastedSource(store)
	now := time.Now()
	src.now = func() time.Time { return now }
	tok := mustToken(t, src, "", "")
	src.Confirm(tok)
	now = now.Add(12 * time.Hour)
	mustToken(t, src, "", "") // renewal before the proof was saved
	src.SaveProof(context.Background())
	if _, found := store.values[proofSecretPrefix+rotationSeed("xoxe-1-seed")]; found {
		t.Fatal("the replacement must not be recorded as accepted")
	}
}

type flakyReads struct {
	*memSecrets
	failReads int
	// failPrefix selects the keys whose reads fail; proof keys by default.
	failPrefix string
}

func (f *flakyReads) GetSecret(ctx context.Context, key string) (string, bool, error) {
	prefix := f.failPrefix
	if prefix == "" {
		prefix = proofSecretPrefix
	}
	if strings.HasPrefix(key, prefix) && f.failReads > 0 {
		f.failReads--
		return "", false, errors.New("vault hiccup")
	}
	return f.memSecrets.GetSecret(ctx, key)
}

func TestProofReadIsRetriedAfterVaultHiccup(t *testing.T) {
	for _, code := range []string{"invalid_auth", "token_expired"} {
		t.Run(code, func(t *testing.T) { proofReadIsRetried(t, code) })
	}
}

func proofReadIsRetried(t *testing.T, code string) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	src := pastedSource(store)
	fresh := mustToken(t, src, "", "")
	accepted := mustToken(t, src, fresh, "token_expired") // spends the forced-refresh budget
	src.Confirm(accepted)
	src.SaveProof(context.Background())

	restarted := newAppTokenSource(rotatingConfig("xoxe.xapp-pasted", "xoxe-1-seed"), &flakyReads{memSecrets: store, failReads: 1})
	mustToken(t, restarted, "", "")
	// The first rejection hits the failing proof read: the stored budget is
	// spent, so nothing is refreshed yet.
	if _, err := restarted.Token(context.Background(), accepted, code); err == nil || slack.refreshCount() != 2 {
		t.Fatalf("err = %v, refreshes = %d; want no refresh while the proof is unreadable", err, slack.refreshCount())
	}
	if got := mustToken(t, restarted, accepted, code); got == accepted || slack.refreshCount() != 3 {
		t.Fatalf("Token = %q, refreshes = %d; the proof must be read on retry and reset the budget", got, slack.refreshCount())
	}
}

func TestUnsavedPairBlocksFurtherRefreshes(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	slack.onRefresh = func() { store.mu.Lock(); store.setErr = errors.New("vault down"); store.mu.Unlock() }
	src := pastedSource(store)
	now := time.Now()
	src.now = func() time.Time { return now }
	tok := mustToken(t, src, "", "")
	src.Confirm(tok)
	now = now.Add(12*time.Hour - refreshMargin/2)
	if got := mustToken(t, src, "", ""); got != tok {
		t.Fatalf("Token = %q; the unexpired token stays in use", got)
	}
	if slack.refreshCount() != 1 {
		t.Fatalf("refreshes = %d; no refresh may spend a refresh token the vault does not hold", slack.refreshCount())
	}
}

func TestLeftoverRefreshTokenLetsFallbackNameMissingCookie(t *testing.T) {
	mode, _ := detectMode(&config{AppRefreshToken: "xoxe-1-x", SessionToken: "xoxc-1"})
	if mode != authModeSession {
		t.Fatalf("mode = %v; with a fallback field filled, a leftover refresh token must not select the app", mode)
	}
}

func TestAmbiguousRejectionAfterFinalRefreshFailureKeepsToken(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.refreshErr = "bad_client_secret"
	src := pastedSource(newMemSecrets())
	// Rejection first, before the worker ever ran.
	if _, err := src.Token(context.Background(), "xoxe.xapp-pasted", "invalid_auth"); err == nil {
		t.Fatal("want the refresh failure reported")
	}
	if got, err := src.Token(context.Background(), "", ""); err != nil || got != "xoxe.xapp-pasted" {
		t.Fatalf("Token = %q, %v; an ambiguous rejection must leave the pasted token in use", got, err)
	}
}

type cancellingStore struct {
	*memSecrets
	cancel context.CancelFunc
}

func (c *cancellingStore) SetSecret(ctx context.Context, key, value string) error {
	err := c.memSecrets.SetSecret(ctx, key, value)
	c.cancel() // the listener stops while the preflight write succeeds
	return err
}

func TestNoExchangeStartsAfterStopDuringPreflight(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	ctx, cancel := context.WithCancel(context.Background())
	src := newAppTokenSource(rotatingConfig("xoxe.xapp-pasted", "xoxe-1-seed"), &cancellingStore{memSecrets: newMemSecrets(), cancel: cancel})
	src.Renew(ctx)
	if slack.refreshCount() != 0 {
		t.Fatalf("refreshes = %d; a stopping listener must not spend a refresh token", slack.refreshCount())
	}
}

func TestMalformedRedirectIsNotEchoed(t *testing.T) {
	prevTransport, prevBase := http.DefaultTransport, slackAPIBase
	http.DefaultTransport = handlerTransport{http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://[bad host xoxe-1-sentinel")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})}
	slackAPIBase = "http://slack.test"
	t.Cleanup(func() { http.DefaultTransport, slackAPIBase = prevTransport, prevBase })
	_, err := refreshAppToken(context.Background(), testClientID, "csecret", "xoxe-1-seed")
	if err == nil || strings.Contains(err.Error(), "sentinel") {
		t.Fatalf("err = %v, want no header text echoed", err)
	}
}

func TestUnreadableRecordIsNeverOverwritten(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	key := rotationSecretPrefix + rotationSeed("xoxe-1-seed")
	store.values[key] = `{"refresh":"xoxe-1-live","expiresAt":"not a time"}`
	src := pastedSource(store)
	src.Renew(context.Background())
	if _, err := src.Token(context.Background(), "", ""); err == nil {
		t.Fatal("want the unreadable record reported")
	}
	if store.values[key] != `{"refresh":"xoxe-1-live","expiresAt":"not a time"}` || slack.refreshCount() != 0 {
		t.Fatalf("record = %q, refreshes = %d; it must be left alone", store.values[key], slack.refreshCount())
	}
}

func TestRunRenewsAtStartAndSavesBeforeReturning(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.access = "xoxe.xapp-pasted" // Slack accepts the pasted token
	slack.socketURL = "bogus://no-dial"
	store := newMemSecrets()
	l := &socketListener{tokens: pastedSource(store)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); l.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for slack.refreshCount() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if slack.refreshCount() != 1 || store.stored(t).Access != "xoxe.xapp-1-access1" {
		t.Fatalf("refreshes = %d, stored = %+v; Run must exchange a pasted token at start and save it before returning", slack.refreshCount(), store.stored(t))
	}
}

func TestDamagedRecordIsNeverOverwritten(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	key := rotationSecretPrefix + rotationSeed("xoxe-1-seed")
	store.values[key] = `{"refresh":"xoxe-1-live","seed":"other"}`
	src := pastedSource(store)
	src.Renew(context.Background())
	if _, err := src.Token(context.Background(), "", ""); err == nil || store.values[key] != `{"refresh":"xoxe-1-live","seed":"other"}` || slack.refreshCount() != 0 {
		t.Fatalf("err = %v, record = %q; a damaged record must be reported and left alone", err, store.values[key])
	}
}

func TestRetryDeadlineSurvivesRestart(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.rateLimit = true
	store := newMemSecrets()
	pastedSource(store).Renew(context.Background())
	pastedSource(store).Renew(context.Background())
	if slack.refreshCount() != 1 {
		t.Fatalf("refreshes = %d; a restart must honour Slack's Retry-After", slack.refreshCount())
	}
}

func TestForeignDiagnosisSurvivesRestart(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.accessKind = "xoxe.xoxb-"
	store := newMemSecrets()
	mustToken(t, pastedSource(store), "", "")
	restarted := pastedSource(store)
	restarted.Renew(context.Background())
	if !strings.Contains(restarted.Warning(), "different token") || slack.refreshCount() != 1 {
		t.Fatalf("Warning = %q, refreshes = %d; a restart must restore the diagnosis without spending the seed again", restarted.Warning(), slack.refreshCount())
	}
}

func TestStringExpiryKeepsTheSuccessor(t *testing.T) {
	if got := expirySeconds(json.RawMessage(`"43200"`)); got != 43200 {
		t.Fatalf("expirySeconds = %d", got)
	}
	if got := expirySeconds(json.RawMessage(`{}`)); got != 0 {
		t.Fatalf("expirySeconds = %d, want the default", got)
	}
}

func TestUnreadableRecordDoesNotEchoContents(t *testing.T) {
	newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	store.values[rotationSecretPrefix+rotationSeed("xoxe-1-seed")] = `{"refresh":"xoxe-1-live","retryAt":"xoxe-1-leaked"}`
	_, err := pastedSource(store).Token(context.Background(), "", "")
	if err == nil || strings.Contains(err.Error(), "leaked") {
		t.Fatalf("err = %v; the record must be reported without its contents", err)
	}
}

func TestRetryDeadlineIsSavedOnceTheVaultRecovers(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.rateLimit = true
	store := newMemSecrets()
	// The vault fails after the preflight write, so the deadline write fails.
	slack.onRefresh = func() {
		store.mu.Lock()
		store.setErr = errors.New("vault down")
		store.mu.Unlock()
	}
	src := pastedSource(store)
	src.Renew(context.Background())
	if !store.stored(t).RetryAt.IsZero() {
		t.Fatal("the deadline write should have failed")
	}
	store.mu.Lock()
	store.setErr = nil
	store.mu.Unlock()
	src.Renew(context.Background()) // within the cooldown: only the write
	if store.stored(t).RetryAt.IsZero() {
		t.Fatal("the deadline must be stored once the vault recovers")
	}
	pastedSource(store).Renew(context.Background())
	if slack.refreshCount() != 1 {
		t.Fatalf("refreshes = %d; a fresh source must honour the stored deadline", slack.refreshCount())
	}
}

func TestPastedAccessTokenBeatsPreflightCopy(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.rateLimit = true
	store := newMemSecrets()
	first := newAppTokenSource(rotatingConfig("", "xoxe-1-seed"), store)
	first.Renew(context.Background())
	slack.access = "xoxe.xapp-pasted"
	if got := mustToken(t, pastedSource(store), "", ""); got != "xoxe.xapp-pasted" {
		t.Fatalf("Token = %q; a newly pasted access token must win over the preflight copy", got)
	}
}

func TestNotAuthedSpendsNoRefreshToken(t *testing.T) {
	if code := rejectionCode(&appTokenError{code: "not_authed"}); code != "" {
		t.Fatalf("rejectionCode = %q; a missing credential must not force an exchange", code)
	}
}

func TestFirstConnectionDoesNotWaitForStartupRenewal(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.access = "xoxe.xapp-pasted"
	gate := make(chan struct{})
	slack.refreshGate = gate
	slack.refreshArrived = make(chan struct{}, 1)
	src := pastedSource(newMemSecrets())
	src.Load(context.Background()) // as Run does before starting the worker
	// Registered after the stub's cleanup, so it runs first: the gate is
	// released and both goroutines are joined, on every exit, before the
	// stub's globals are restored.
	var wg sync.WaitGroup
	t.Cleanup(func() { close(gate); wg.Wait() })
	wg.Add(1)
	go func() { defer wg.Done(); src.Renew(context.Background()) }()
	select {
	case <-slack.refreshArrived: // the worker now holds the source mutex
	case <-time.After(5 * time.Second):
		t.Fatal("the startup renewal never reached the exchange")
	}
	l := &socketListener{tokens: src}
	opened := make(chan error, 1)
	wg.Add(1)
	go func() { defer wg.Done(); _, err := l.openConnection(context.Background()); opened <- err }()
	select {
	case err := <-opened:
		if err != nil {
			t.Errorf("openConnection: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("apps.connections.open waited for the in-flight exchange")
	}
}

func TestMalformedAccessTokenKeepsTheSuccessor(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.rawAccess = `{"bad":1}`
	slack.tokenType = "bot"
	store := newMemSecrets()
	pastedSource(store).Renew(context.Background())
	var kept rotatingPair
	if err := json.Unmarshal([]byte(store.values[foreignSecretPrefix+rotationSeed("xoxe-1-seed")]), &kept); err != nil || kept.Refresh != "xoxe-1-refresh1" {
		t.Fatalf("kept = %+v, %v; the successor refresh token must be kept", kept, err)
	}
}

func TestReplacementSlackCallsExpiredStops(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	src := pastedSource(newMemSecrets())
	first := mustToken(t, src, "", "")
	second := mustToken(t, src, first, "token_expired")
	if _, err := src.Token(context.Background(), second, "token_expired"); err == nil {
		t.Fatal("want an error")
	}
	if tok, err := src.Token(context.Background(), "", ""); err == nil {
		t.Fatalf("Token = %q; a replacement Slack also called expired must not be retried", tok)
	}
	if slack.refreshCount() != 2 {
		t.Fatalf("refreshes = %d, want 2", slack.refreshCount())
	}
}

func TestRefreshTokenWithoutAccessTokenIsKept(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.emptyAccess = true
	slack.tokenType = "bot"
	store := newMemSecrets()
	src := pastedSource(store)
	src.Renew(context.Background())
	var kept rotatingPair
	if err := json.Unmarshal([]byte(store.values[foreignSecretPrefix+rotationSeed("xoxe-1-seed")]), &kept); err != nil || kept.Refresh != "xoxe-1-refresh1" {
		t.Fatalf("kept = %+v, %v; the successor refresh token must be kept", kept, err)
	}
	if store.stored(t).Refresh != "xoxe-1-seed" {
		t.Fatal("an incomplete pair must never become the chain")
	}
}

func TestAcceptedTokenClearsForcedRefreshWarning(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	src := pastedSource(newMemSecrets())
	got := mustToken(t, src, "", "")
	src.Confirm(got)
	slack.mu.Lock()
	slack.refreshErr = "service_unavailable"
	slack.mu.Unlock()
	if _, err := src.Token(context.Background(), got, "invalid_auth"); err == nil {
		t.Fatal("want the forced refresh to fail")
	}
	if src.Warning() == "" {
		t.Fatal("want a retrying warning")
	}
	src.Confirm(got) // Slack accepted the same token again
	src.Renew(context.Background())
	if w := src.Warning(); w != "" {
		t.Fatalf("Warning = %q; it must clear once Slack accepts the token again", w)
	}
}

func TestSavedSettingsReachTheExchange(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	cfg, err := loadConfig(map[string]any{"app_token": "xoxe.xapp-pasted", "app_refresh_token": "xoxe-1-seed", "client_id": testClientID, "client_secret": "csecret", "bot_token": "xoxb-1", "utility_agent": "a"})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	store := newMemSecrets()
	newAppTokenSource(cfg, store).Renew(context.Background())
	if slack.refreshCount() != 1 || store.stored(t).Refresh != "xoxe-1-refresh1" {
		t.Fatalf("refreshes = %d, stored = %+v; configured client credentials must reach Slack", slack.refreshCount(), store.stored(t))
	}
}

func TestExpiredTokenWithDeadRefreshTokenStops(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	src := pastedSource(newMemSecrets())
	got := mustToken(t, src, "", "")
	slack.mu.Lock()
	slack.refreshErr = "invalid_refresh_token"
	slack.mu.Unlock()
	if _, err := src.Token(context.Background(), got, "token_expired"); err == nil {
		t.Fatal("want the failed renewal reported")
	}
	if tok, err := src.Token(context.Background(), "", ""); err == nil {
		t.Fatalf("Token = %q; a token Slack called expired must not be retried once renewal is impossible", tok)
	}
}

func TestTokenSlackCalledDeadIsNotResent(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	src := pastedSource(newMemSecrets())
	now := time.Now()
	src.now = func() time.Time { return now }
	tok := mustToken(t, src, "", "")
	slack.mu.Lock()
	slack.refreshErr = "service_unavailable"
	slack.mu.Unlock()
	if _, err := src.Token(context.Background(), tok, "token_expired"); err == nil {
		t.Fatal("want the failed renewal reported")
	}
	if got, err := src.Token(context.Background(), "", ""); err == nil {
		t.Fatalf("Token = %q; a token Slack called expired must not be resent", got)
	}
	slack.mu.Lock()
	slack.refreshErr = ""
	slack.mu.Unlock()
	now = now.Add(refreshCooldown + time.Second)
	got, err := src.Token(context.Background(), "", "")
	if err != nil || got == tok {
		t.Fatalf("Token = %q, %v; renewal must resume after the cooldown", got, err)
	}
	// The failed forced refresh was charged: rejecting the successor too
	// spends nothing more.
	if _, err := src.Token(context.Background(), got, "token_expired"); err == nil || slack.refreshCount() != 3 {
		t.Fatalf("err = %v, refreshes = %d; the forced-refresh budget must carry over", err, slack.refreshCount())
	}
}

func TestTwiceRejectedChainForcesNoImmediateRefresh(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	src := pastedSource(store)
	first := mustToken(t, src, "", "")
	second := mustToken(t, src, first, "token_expired")
	if _, err := src.Token(context.Background(), second, "token_expired"); err == nil {
		t.Fatal("want the replacement reported dead")
	}
	restarted := pastedSource(store)
	restarted.Renew(context.Background())
	if _, err := restarted.Token(context.Background(), "", ""); err == nil || slack.refreshCount() != 2 {
		t.Fatalf("err = %v, refreshes = %d; a restart must neither resend the dead token nor force a refresh", err, slack.refreshCount())
	}
	// Its proof may only have failed to save: the scheduled renewal still
	// runs, once.
	restarted.now = func() time.Time { return time.Now().Add(12 * time.Hour) }
	restarted.Renew(context.Background())
	if slack.refreshCount() != 3 {
		t.Fatalf("refreshes = %d; the scheduled renewal must still run", slack.refreshCount())
	}
}

func TestRetriedConnectionRejectionIsRecorded(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	src := pastedSource(newMemSecrets())
	l := &socketListener{tokens: src}
	slack.rejectOpen = true
	if _, err := l.openConnection(context.Background()); err == nil {
		t.Fatal("want both attempts rejected")
	}
	var sent []string
	slack.onOpen = func(tok string) { sent = append(sent, tok) }
	_, _ = l.openConnection(context.Background())
	for _, tok := range sent {
		if tok == "xoxe.xapp-1-access1" {
			t.Fatalf("sent %v; the replacement Slack called expired was resent", sent)
		}
	}
}

func TestPastedTokenSlackCalledExpiredIsNotResent(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.refreshErr = "service_unavailable"
	src := pastedSource(newMemSecrets())
	if _, err := src.Token(context.Background(), "xoxe.xapp-pasted", "token_expired"); err == nil {
		t.Fatal("want the failed renewal reported")
	}
	if got, err := src.Token(context.Background(), "", ""); err == nil {
		t.Fatalf("Token = %q; a pasted token Slack called expired must not be resent", got)
	}
}

func TestQuarantineReasonSurvivesRestart(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.emptyAccess = true
	slack.tokenType = "bot"
	store := newMemSecrets()
	pastedSource(store).Renew(context.Background())
	restarted := pastedSource(store)
	restarted.Renew(context.Background())
	if w := restarted.Warning(); !strings.Contains(w, "without an access token") {
		t.Fatalf("Warning = %q; the restored diagnosis must match the original", w)
	}
}

func TestQuarantineAfterALaterRotationSurvivesRestart(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	src := pastedSource(store)
	now := time.Now()
	src.now = func() time.Time { return now }
	mustToken(t, src, "", "")
	slack.mu.Lock()
	slack.rawAccess = `7`
	slack.tokenType = "bot"
	slack.mu.Unlock()
	now = now.Add(12 * time.Hour)
	src.Renew(context.Background())
	restarted := pastedSource(store)
	restarted.Renew(context.Background())
	if w := restarted.Warning(); !strings.Contains(w, foreignSecretPrefix) || slack.refreshCount() != 2 {
		t.Fatalf("Warning = %q, refreshes = %d; the quarantined successor must be reported, the spent token left alone", w, slack.refreshCount())
	}
}

func TestDeadTokenIsNotResentWhileProofIsUnreadable(t *testing.T) {
	newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	tok := mustToken(t, pastedSource(store), "", "")
	restarted := newAppTokenSource(rotatingConfig("xoxe.xapp-pasted", "xoxe-1-seed"), &flakyReads{memSecrets: store, failReads: 10})
	restarted.loaded, restarted.cur, restarted.proofPending = true, store.stored(t), true
	_, _ = restarted.Token(context.Background(), tok, "token_expired")
	if got, err := restarted.Token(context.Background(), "", ""); err == nil && got == tok {
		t.Fatal("a token Slack called expired was resent while the proof was unreadable")
	}
}

func TestCooldownKeepsTheOriginalFailure(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.refreshErr = "service_unavailable"
	src := newAppTokenSource(rotatingConfig("", "xoxe-1-seed"), newMemSecrets())
	_, _ = src.Token(context.Background(), "", "")
	_, _ = src.Token(context.Background(), "", "")
	if w := src.Warning(); !strings.Contains(w, "service_unavailable") || strings.Contains(w, "retrying in") {
		t.Fatalf("Warning = %q; the cooldown must not replace the original cause", w)
	}
}

func TestRejectedDeadTokensSpendOneRefreshAcrossReconnects(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	src := pastedSource(newMemSecrets())
	l := &socketListener{tokens: src}
	mustToken(t, src, "", "")
	slack.rejectOpen = true
	before := slack.refreshCount()
	for range 4 {
		_, _ = l.openConnection(context.Background())
	}
	if got := slack.refreshCount() - before; got != 1 {
		t.Fatalf("refreshes = %d; Slack rejecting every token may cost one refresh token before the schedule", got)
	}
}

func TestUnreadableQuarantineRecordDoesNotStopTheChain(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	store.values[foreignSecretPrefix+rotationSeed("xoxe-1-seed")] = `{"refr`
	src := pastedSource(store)
	src.Renew(context.Background())
	if slack.refreshCount() != 1 || src.Warning() != "" || store.values[foreignSecretPrefix+rotationSeed("xoxe-1-seed")] != `{"refr` {
		t.Fatalf("refreshes = %d, Warning = %q; a damaged quarantine record must neither stop the chain nor be overwritten", slack.refreshCount(), src.Warning())
	}
}

func TestFailedBootstrapKeepsTheFirstTokensBudget(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.refreshErr = "service_unavailable"
	src := pastedSource(newMemSecrets())
	now := time.Now()
	src.now = func() time.Time { return now }
	if _, err := src.Token(context.Background(), "xoxe.xapp-pasted", "token_expired"); err == nil {
		t.Fatal("want the failed bootstrap reported")
	}
	slack.mu.Lock()
	slack.refreshErr = ""
	slack.mu.Unlock()
	now = now.Add(refreshCooldown + time.Second)
	first, err := src.Token(context.Background(), "", "")
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got, err := src.Token(context.Background(), first, "token_expired"); err != nil || got == first {
		t.Fatalf("Token = %q, %v; the first issued token must keep its one forced refresh", got, err)
	}
}

func TestLiveAcceptanceOutranksAnUnreadableProof(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	src := pastedSource(store)
	first := mustToken(t, src, "", "")
	second := mustToken(t, src, first, "token_expired") // spends the stored budget
	restarted := newAppTokenSource(rotatingConfig("xoxe.xapp-pasted", "xoxe-1-seed"), &flakyReads{memSecrets: store, failReads: 10})
	restarted.Load(context.Background())
	restarted.Confirm(second)
	if got, err := restarted.Token(context.Background(), second, "token_expired"); err != nil || got == second || slack.refreshCount() != 3 {
		t.Fatalf("Token = %q, %v, refreshes = %d; a token seen accepted must be renewed despite an unreadable proof", got, err, slack.refreshCount())
	}
}

func TestMalformedMetadataKeepsTheSuccessorPair(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.extraFields = `"error":{"x":1},"warning":7,`
	store := newMemSecrets()
	pastedSource(store).Renew(context.Background())
	if got := store.stored(t); got.Refresh != "xoxe-1-refresh1" {
		t.Fatalf("stored = %+v; malformed metadata must not discard the successor", got)
	}
}

func TestTransientFailureKeepsTheScheduledBudget(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	src := pastedSource(newMemSecrets())
	now := time.Now()
	src.now = func() time.Time { return now }
	tok := mustToken(t, src, "", "")
	src.Confirm(tok)
	src.Renew(context.Background()) // folds the proof
	slack.mu.Lock()
	slack.refreshErr = "service_unavailable"
	slack.mu.Unlock()
	if _, err := src.Token(context.Background(), tok, "token_expired"); err == nil {
		t.Fatal("want the failed exchange reported")
	}
	slack.mu.Lock()
	slack.refreshErr = ""
	slack.mu.Unlock()
	now = now.Add(refreshCooldown + time.Second)
	next, err := src.Token(context.Background(), "", "")
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got, err := src.Token(context.Background(), next, "token_expired"); err != nil || got == next {
		t.Fatalf("Token = %q, %v; the successor must keep its forced refresh", got, err)
	}
}

func TestExplicitRejectionWithTerminalRenewalSurvivesRestart(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	src := pastedSource(store)
	tok := mustToken(t, src, "", "")
	slack.mu.Lock()
	slack.refreshErr = "invalid_refresh_token"
	slack.mu.Unlock()
	_, _ = src.Token(context.Background(), tok, "token_expired")
	if got, err := pastedSource(store).Token(context.Background(), "", ""); err == nil && got == tok {
		t.Fatal("a restart resent the token Slack called expired")
	}
}

func TestProofReadAfterHiccupRestoresTheSuccessorsBudget(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	src := pastedSource(store)
	first := mustToken(t, src, "", "")
	accepted := mustToken(t, src, first, "token_expired")
	src.Confirm(accepted)
	src.SaveProof(context.Background())
	restarted := newAppTokenSource(rotatingConfig("xoxe.xapp-pasted", "xoxe-1-seed"), &flakyReads{memSecrets: store, failReads: 1})
	restarted.Load(context.Background())
	if _, err := restarted.Token(context.Background(), accepted, "token_expired"); err == nil {
		t.Fatal("want the unreadable proof reported")
	}
	next, err := restarted.Token(context.Background(), "", "") // ordinary reconnect
	if err != nil || next == accepted {
		t.Fatalf("Token = %q, %v; the reconnect must renew once the proof is read", next, err)
	}
	if got, err := restarted.Token(context.Background(), next, "token_expired"); err != nil || got == next {
		t.Fatalf("Token = %q, %v, refreshes = %d; the successor must keep its forced refresh", got, err, slack.refreshCount())
	}
}

func TestTruncatedReplyKeepsTheSuccessor(t *testing.T) {
	for _, mode := range []string{"clean", "short"} {
		t.Run(mode, func(t *testing.T) {
			slack := newRotationSlack(t, "xoxe-1-seed")
			slack.truncate = mode
			store := newMemSecrets()
			src := pastedSource(store)
			got := mustToken(t, src, "", "")
			if stored := store.stored(t); got != "xoxe.xapp-1-access1" || stored.Refresh != "xoxe-1-refresh1" || stored.Access != got {
				t.Fatalf("Token = %q, stored = %+v; a reply cut off after the successor must still yield the pair", got, stored)
			}
		})
	}
}

func TestRevokedRefreshTokenIsNotResent(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	src := pastedSource(newMemSecrets())
	now := time.Now()
	src.now = func() time.Time { return now }
	tok := mustToken(t, src, "", "")
	slack.mu.Lock()
	slack.refreshErr = "token_revoked"
	slack.mu.Unlock()
	now = now.Add(12*time.Hour - refreshMargin)
	src.Renew(context.Background())
	if w := src.Warning(); !strings.Contains(w, "cannot be renewed") || !strings.Contains(w, "Generate a new app-level token") {
		t.Fatalf("Warning = %q; a revoked refresh token must be reported as needing a new pair", w)
	}
	if got, err := src.Token(context.Background(), "", ""); err != nil || got != tok {
		t.Fatalf("Token = %q, %v; the still-valid access token stays in use", got, err)
	}
	now = now.Add(time.Hour)
	src.Renew(context.Background())
	if slack.refreshCount() != 2 {
		t.Fatalf("refreshes = %d; a revoked refresh token must not be resent", slack.refreshCount())
	}
}

func TestUnreadableQuarantineSecretKeepsTheStoredToken(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	now := time.Now()
	src := pastedSource(store)
	src.now = func() time.Time { return now }
	tok := mustToken(t, src, "", "")
	reads := &flakyReads{memSecrets: store, failReads: 1000, failPrefix: foreignSecretPrefix}
	restarted := newAppTokenSource(rotatingConfig("xoxe.xapp-pasted", "xoxe-1-seed"), reads)
	restarted.now = src.now
	restarted.Load(context.Background())
	if got, err := restarted.Token(context.Background(), "", ""); err != nil || got != tok {
		t.Fatalf("Token = %q, %v; the stored token needs no exchange and must be offered", got, err)
	}
	now = now.Add(12 * time.Hour)
	restarted.Renew(context.Background())
	if slack.refreshCount() != 1 || !strings.Contains(restarted.Warning(), "not attempted") {
		t.Fatalf("refreshes = %d, Warning = %q; no exchange may start before the quarantine record is read", slack.refreshCount(), restarted.Warning())
	}
	reads.failReads = 0
	restarted.Renew(context.Background())
	if slack.refreshCount() != 2 {
		t.Fatalf("refreshes = %d; the renewal must proceed once the record is readable", slack.refreshCount())
	}
}

func TestQuarantineReadLateStillStopsTheChain(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.emptyAccess = true
	slack.tokenType = "bot"
	store := newMemSecrets()
	now := time.Now()
	src := pastedSource(store)
	src.now = func() time.Time { return now }
	src.Renew(context.Background())
	reads := &flakyReads{memSecrets: store, failReads: 1, failPrefix: foreignSecretPrefix}
	restarted := newAppTokenSource(rotatingConfig("xoxe.xapp-pasted", "xoxe-1-seed"), reads)
	now = now.Add(refreshCooldown + time.Second)
	restarted.now = src.now
	restarted.Load(context.Background())
	restarted.Renew(context.Background())
	if w := restarted.Warning(); slack.refreshCount() != 1 || !strings.Contains(w, foreignSecretPrefix) {
		t.Fatalf("refreshes = %d, Warning = %q; a quarantine found late must still keep the spent token unused", slack.refreshCount(), w)
	}
}

func TestRejectionInRenewalWindowKeepsTheSuccessorsBudget(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	src := pastedSource(newMemSecrets())
	now := time.Now()
	src.now = func() time.Time { return now }
	first := mustToken(t, src, "", "")
	src.Confirm(first)
	// The scheduled renewal is due, but the worker has not ticked yet.
	now = now.Add(12*time.Hour - refreshMargin + time.Minute)
	second, err := src.Token(context.Background(), first, "invalid_auth")
	if err != nil || second == first {
		t.Fatalf("Token = %q, %v; want the due renewal", second, err)
	}
	if third, err := src.Token(context.Background(), second, "token_expired"); err != nil || third == second || slack.refreshCount() != 3 {
		t.Fatalf("Token = %q, %v, refreshes = %d; a renewal a reconnect made must keep the successor's forced refresh", third, err, slack.refreshCount())
	}
}

func TestAppLevelReplyWithoutAccessTokenContinuesTheChain(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	now := time.Now()
	clock := func() time.Time { return now }
	src := pastedSource(store)
	src.now = clock
	first := mustToken(t, src, "", "")
	slack.mu.Lock()
	slack.emptyAccess = true
	slack.mu.Unlock()
	now = now.Add(12*time.Hour - refreshMargin) // the scheduled renewal is due
	src.Renew(context.Background())
	if stored := store.stored(t); stored.Refresh != "xoxe-1-refresh2" || stored.Access != first {
		t.Fatalf("stored = %+v; the app-level successor must join the still-valid access token", stored)
	}
	if _, found := store.values[foreignSecretPrefix+rotationSeed("xoxe-1-seed")]; found || src.Warning() == "" {
		t.Fatalf("Warning = %q; an app-level successor is reported, not quarantined", src.Warning())
	}
	if got, err := src.Token(context.Background(), "", ""); err != nil || got != first {
		t.Fatalf("Token = %q, %v; the current access token stays in use", got, err)
	}
	// A second such reply doubles the wait, and a restart keeps it.
	now = now.Add(refreshCooldown)
	src.Renew(context.Background())
	slack.mu.Lock()
	slack.emptyAccess = false
	slack.mu.Unlock()
	restarted := pastedSource(store)
	restarted.now = clock
	now = now.Add(refreshCooldown)
	restarted.Renew(context.Background())
	if slack.refreshCount() != 3 {
		t.Fatalf("refreshes = %d; the doubled wait must survive a restart", slack.refreshCount())
	}
	now = now.Add(refreshCooldown)
	if got := mustToken(t, restarted, "", ""); got != "xoxe.xapp-1-access4" || slack.refreshCount() != 4 {
		t.Fatalf("Token = %q, refreshes = %d; the stored successor must be exchanged once the wait passes", got, slack.refreshCount())
	}
}

func TestReplyWithoutAccessTokenKeepsTheForcedBudget(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	src := pastedSource(newMemSecrets())
	now := time.Now()
	src.now = func() time.Time { return now }
	first := mustToken(t, src, "", "")
	slack.mu.Lock()
	slack.emptyAccess = true
	slack.mu.Unlock()
	if _, err := src.Token(context.Background(), first, "token_expired"); err == nil {
		t.Fatal("want the missing access token reported")
	}
	slack.mu.Lock()
	slack.emptyAccess = false
	slack.mu.Unlock()
	now = now.Add(refreshCooldown + time.Second)
	third, err := src.Token(context.Background(), "", "")
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if _, err := src.Token(context.Background(), third, "token_expired"); err == nil || slack.refreshCount() != 3 {
		t.Fatalf("err = %v, refreshes = %d; the forced refresh already spent must not be granted again", err, slack.refreshCount())
	}
}

func TestUnsavedProofDelaysRecoveryOnlyBriefly(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	now := time.Now()
	clock := func() time.Time { return now }
	src := pastedSource(store)
	src.now = clock
	first := mustToken(t, src, "", "")
	second := mustToken(t, src, first, "token_expired") // spends the forced refresh
	src.Confirm(second)
	store.mu.Lock()
	store.setErr = errors.New("vault down")
	store.mu.Unlock()
	src.SaveProof(context.Background())
	store.mu.Lock()
	store.setErr = nil
	store.mu.Unlock()
	// After a restart Slack calls the accepted replacement dead.
	restarted := pastedSource(store)
	restarted.now = clock
	if _, err := restarted.Token(context.Background(), second, "token_expired"); err == nil || slack.refreshCount() != 2 {
		t.Fatalf("err = %v, refreshes = %d; a spent budget forces nothing at once", err, slack.refreshCount())
	}
	again := pastedSource(store) // a further restart must not skip the delay
	again.now = clock
	if _, err := again.Token(context.Background(), "", ""); err == nil || slack.refreshCount() != 2 {
		t.Fatalf("err = %v, refreshes = %d; the delay must survive a restart", err, slack.refreshCount())
	}
	now = now.Add(recoveryDelay)
	third, err := again.Token(context.Background(), "", "")
	if err != nil || third == second || slack.refreshCount() != 3 {
		t.Fatalf("Token = %q, %v, refreshes = %d; recovery must follow the delay, not wait for the scheduled renewal", third, err, slack.refreshCount())
	}
	// Slack calling the recovered token dead too doubles the delay.
	if _, err := again.Token(context.Background(), third, "token_expired"); err == nil {
		t.Fatal("want the recovered token reported dead")
	}
	now = now.Add(recoveryDelay)
	if _, err := again.Token(context.Background(), "", ""); err == nil || slack.refreshCount() != 3 {
		t.Fatalf("err = %v, refreshes = %d; the second delay is twice as long", err, slack.refreshCount())
	}
	now = now.Add(recoveryDelay)
	if _, err := again.Token(context.Background(), "", ""); err != nil || slack.refreshCount() != 4 {
		t.Fatalf("err = %v, refreshes = %d; recovery must follow the doubled delay", err, slack.refreshCount())
	}
}

func TestRefreshInvalidAuthNamesItsRemedy(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.refreshErr = "invalid_auth"
	src := pastedSource(newMemSecrets())
	src.Renew(context.Background())
	if w := src.Warning(); !strings.Contains(w, "invalid_auth") || !strings.Contains(w, "IP allowlist") {
		t.Fatalf("Warning = %q; Slack's invalid_auth must name what to check", w)
	}
}

func TestUnsavedPairWarningReachesTheStatus(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	store := newMemSecrets()
	slack.onRefresh = func() { store.mu.Lock(); store.setErr = errors.New("vault down"); store.mu.Unlock() }
	src := pastedSource(store)
	src.Renew(context.Background())
	host := newFakeHost(nil)
	sup := newSupervisor(func() pluginsdk.Host { return host })
	sup.tokens = src
	cfg := rotatingConfig("xoxe.xapp-pasted", "xoxe-1-seed")
	// Before the listener has reported anything.
	sup.publishSocketStatus(context.Background(), host, cfg)
	if st := readStatus(context.Background(), host); !strings.Contains(st.Error, "could not be saved yet") {
		t.Fatalf("status = %+v; the unsaved pair must be reported before the listener reports", st)
	}
	// Next to a connection error.
	sup.noteSocketState(false, errors.New("open socket connection: boom"))
	sup.publishSocketStatus(context.Background(), host, cfg)
	if st := readStatus(context.Background(), host); !strings.Contains(st.Error, "boom") || !strings.Contains(st.Error, "(also: ") || !strings.Contains(st.Error, "could not be saved yet") {
		t.Fatalf("status = %+v; the unsaved pair must be reported next to the socket error", st)
	}
}

func TestTerminalRenewalFailureIsShownOnce(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.refreshErr = "invalid_refresh_token"
	src := pastedSource(newMemSecrets())
	_, err := src.Token(context.Background(), "xoxe.xapp-pasted", "token_expired")
	if err == nil {
		t.Fatal("want the terminal renewal failure")
	}
	host := newFakeHost(nil)
	sup := newSupervisor(func() pluginsdk.Host { return host })
	sup.tokens = src
	sup.noteSocketState(false, fmt.Errorf("open socket connection: %w", err))
	sup.publishSocketStatus(context.Background(), host, rotatingConfig("xoxe.xapp-pasted", "xoxe-1-seed"))
	st := readStatus(context.Background(), host)
	if strings.Count(st.Error, "invalid_refresh_token") != 1 || strings.Contains(st.Error, "(also: ") {
		t.Fatalf("status error = %q; the failure the listener reported must not be repeated", st.Error)
	}
}

func TestLostReplyIsReplayedWithinTheGracePeriod(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.lostReplies = 1
	store := newMemSecrets()
	src := pastedSource(store)
	got := mustToken(t, src, "", "")
	stored := store.stored(t)
	if slack.refreshCount() != 2 || got != "xoxe.xapp-1-access2" || stored.Refresh != "xoxe-1-refresh2" || src.Warning() != "" {
		t.Fatalf("Token = %q, refreshes = %d, stored = %+v, Warning = %q; a lost reply must be replayed at once, while the redeemed token still works", got, slack.refreshCount(), stored, src.Warning())
	}
}

func TestRepeatedLostReplyWaitsForTheCooldown(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.lostReplies = 2
	src := pastedSource(newMemSecrets())
	now := time.Now()
	src.now = func() time.Time { return now }
	src.Renew(context.Background())
	src.Renew(context.Background())
	if slack.refreshCount() != 2 || !strings.Contains(src.Warning(), "request to Slack failed") {
		t.Fatalf("refreshes = %d, Warning = %q; one immediate replay, then the cooldown", slack.refreshCount(), src.Warning())
	}
}

func TestAmbiguousServerFailureIsReplayedAtOnce(t *testing.T) {
	for _, lostAs := range []string{"502", "internal_error"} {
		t.Run(lostAs, func(t *testing.T) {
			slack := newRotationSlack(t, "xoxe-1-seed")
			slack.lostReplies, slack.lostAs = 1, lostAs
			store := newMemSecrets()
			src := pastedSource(store)
			got := mustToken(t, src, "", "")
			if slack.refreshCount() != 2 || got != "xoxe.xapp-1-access2" || store.stored(t).Refresh != "xoxe-1-refresh2" {
				t.Fatalf("Token = %q, refreshes = %d; Slack may have redeemed the token, so it must be replayed at once", got, slack.refreshCount())
			}
		})
	}
}

func TestStoppedListenerSkipsTheReplay(t *testing.T) {
	slack := newRotationSlack(t, "xoxe-1-seed")
	slack.lostReplies = 1
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	slack.onRefresh = cancel // the listener stops while Slack answers
	store := newMemSecrets()
	src := pastedSource(store)
	src.Renew(ctx)
	if slack.refreshCount() != 1 || store.stored(t).RetryAt.IsZero() {
		t.Fatalf("refreshes = %d, stored = %+v; no replay may start once the listener is stopping, and the cooldown is saved", slack.refreshCount(), store.stored(t))
	}
}
