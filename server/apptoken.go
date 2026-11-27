package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Slack apps with token rotation enabled issue app-level tokens that expire
// (12 hours) together with a single-use refresh token. Every refresh returns a
// new access token and a new refresh token and invalidates the old refresh
// token, so the newest pair must be persisted before it is used: losing it
// breaks the chain and the operator has to generate a fresh token by hand.
// A process killed between Slack's answer and the save still loses the chain;
// nothing on this side of the API can close that window.
//
// https://docs.slack.dev/authentication/using-token-rotation/

// rotationSecretPrefix names the plugin-owned secrets holding the current
// pair, one per configured refresh token (suffixed by its seed). Both tokens
// live in one JSON value so a single SetSecret commits them together; two
// separate secrets could be left mismatched by a crash between writes. Keying
// by seed keeps an earlier chain intact while a newly pasted one is tried, so
// restoring the earlier settings still works.
const rotationSecretPrefix = "app_token_rotation."

// vaultTimeout bounds one secret read or write.
const vaultTimeout = 15 * time.Second

const (
	// refreshMargin is how long before expiry the access token is replaced.
	refreshMargin = 10 * time.Minute
	// renewInterval is how often a live connection checks the expiry, so the
	// token is renewed on schedule even while no reconnect happens.
	renewInterval = time.Minute
	// exchangeTimeout bounds one Slack refresh request.
	exchangeTimeout = requestTimeout + 5*time.Second
	saveAttempts    = 3
	// saveTimeout bounds saving a refresh's result: every attempt plus the
	// backoff between them, measured from Slack's answer.
	saveTimeout = saveAttempts*vaultTimeout + 3*time.Second
	// defaultRetryAfter applies when Slack rate-limits without a header.
	defaultRetryAfter = time.Minute
	// refreshCooldown spaces out exchanges after any other failure.
	refreshCooldown = 30 * time.Second
)

// secretStore is the subset of pluginsdk.Host the token source needs.
type secretStore interface {
	GetSecret(ctx context.Context, key string) (string, bool, error)
	SetSecret(ctx context.Context, key, value string) error
}

// rotatingPair is the persisted state of a rotating app-level token.
type rotatingPair struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
	// ExpiresAt is Slack's expiry for a token this plugin obtained by
	// refreshing. It is zero for the access token the operator pasted, whose
	// expiry is unknown.
	ExpiresAt time.Time `json:"expiresAt,omitzero"`
	// Seed identifies the refresh token the operator configured. When the
	// operator pastes a new pair the seed changes and the stored chain is
	// discarded in favour of the configured tokens.
	Seed string `json:"seed"`
	// Proven is set once Access opened a socket. A freshly issued token
	// that Slack rejects before that gets at most one more refresh. It is
	// stored under its own key (proofSecretPrefix) rather than with the
	// pair, so saving it can never race a newer pair's save.
	Proven bool `json:"-"`
	// Retries counts refreshes forced by Slack calling an unproven token
	// expired. It travels with the chain so a restart cannot reset it, and
	// caps how many refresh tokens such rejections can spend.
	Retries int `json:"retries,omitempty"`
	// Reason, on a quarantined successor only, is why it was not used.
	Reason string `json:"reason,omitempty"`
	// Replaced, on a quarantined successor only, is the digest of the
	// refresh token it replaced.
	Replaced string `json:"replaced,omitempty"`
	// Dead marks an access token Slack called expired or revoked; it is
	// never offered again.
	Dead bool `json:"dead,omitempty"`
	// NextRetries is the forced-refresh count the exchange replacing a dead
	// token carries, decided when Slack rejected it.
	NextRetries int `json:"nextRetries,omitempty"`
	// DeadCode is Slack's error code for a dead token.
	DeadCode string `json:"deadCode,omitempty"`
	// DeadAt is when Slack called the token dead; a spent forced-refresh
	// budget delays the next exchange from then (recoveryAt).
	DeadAt time.Time `json:"deadAt,omitzero"`
	// Incomplete counts consecutive refreshes that returned a successor
	// refresh token without an access token; each doubles the wait before
	// the next exchange.
	Incomplete int `json:"incomplete,omitempty"`
	// RetryAt is when the next exchange may be attempted after a failure or
	// Slack rate limit. Stored so a restart honours it.
	RetryAt time.Time `json:"retryAt,omitzero"`
}

// issued reports whether Slack handed this access token to the plugin.
func (p rotatingPair) issued() bool { return !p.ExpiresAt.IsZero() }

// appTokenSource hands the Socket Mode listener a usable app-level token. A
// static xapp- token is returned as-is. A rotating token is exchanged once at
// start to learn its expiry, renewed ahead of that expiry, and refreshed on
// demand when Slack rejects it. Calls are serialized: two concurrent refreshes
// would each spend the same single-use refresh token.
type appTokenSource struct {
	static string

	rotating     bool
	seed         string
	initial      rotatingPair
	clientID     string
	clientSecret string
	store        secretStore
	now          func() time.Time

	mu     sync.Mutex
	cur    rotatingPair
	loaded bool
	// unsaved is set when a refreshed pair is not in the vault yet, the case
	// where a restart would lose the chain; the save is retried on every
	// later call until it lands.
	unsaved bool
	// proofDirty is set when the current token's proof is not saved yet.
	proofDirty bool
	// proofPending is set while the stored token's proof could not be read.
	proofPending bool
	// saveFailed is set when a save attempt failed, for the status page.
	saveFailed bool
	// foreignPending is a successor pair of another token kind whose save
	// failed; it is retried like an unsaved pair.
	foreignPending *rotatingPair
	// foreignMsg is the diagnosis of a foreign refresh token, kept to
	// update the terminal error once its successor is saved.
	foreignMsg string
	// foreignUnchecked is set while the quarantine record could not be
	// read; no exchange starts until it has been.
	foreignUnchecked bool
	// metaUnsaved marks a retry deadline that could not be stored yet.
	metaUnsaved bool
	// confirms counts Confirm calls; failedAt is its value at the last
	// renewal failure, so only a later acceptance clears that warning.
	confirms atomic.Uint64
	failedAt uint64
	// renewErr is a refresh failure retrying cannot fix. The current access
	// token stays in use until it expires or Slack rejects it.
	renewErr error
	// terminal stops the source: no usable token is left and only new
	// credentials can help. Saving them builds a new source.
	terminal error
	// retryAt is when Slack allows the next refresh after rate limiting.
	retryAt time.Time
	// lastRenewErr is the latest transient renewal failure, cleared by a
	// successful refresh.
	lastRenewErr string
	// warning mirrors Warning() so the status page can read it without
	// waiting behind an exchange holding mu.
	warning atomic.Pointer[[]warningPart]
	// usable is the current token for Token's lock-free path, nil when
	// there is none or the source is terminal.
	usable atomic.Pointer[rotatingPair]
	// confirmed is the last token that opened a socket. It is recorded
	// without mu so the listener never waits on a renewal before dialing.
	confirmed atomic.Pointer[string]
}

func newAppTokenSource(cfg *config, store secretStore) *appTokenSource {
	if !cfg.rotatesAppToken() {
		return &appTokenSource{static: cfg.AppToken}
	}
	seed := rotationSeed(cfg.AppRefreshToken)
	return &appTokenSource{
		rotating:     true,
		seed:         seed,
		initial:      rotatingPair{Access: cfg.AppToken, Refresh: cfg.AppRefreshToken, Seed: seed},
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		store:        store,
		now:          time.Now,
	}
}

// rotationSeed fingerprints the configured refresh token without storing it.
func rotationSeed(refresh string) string {
	sum := sha256.Sum256([]byte(refresh))
	return hex.EncodeToString(sum[:8])
}

// Rotating reports whether rejected tokens can be recovered by a refresh.
func (s *appTokenSource) Rotating() bool { return s.rotating }

// Token returns the access token to open the next connection with. When Slack
// refused a token, rejected is that token and code Slack's error code; both
// are empty otherwise. Proactive renewal is left to Renew, so a reconnect
// never waits for it while the current token is still usable.
func (s *appTokenSource) Token(ctx context.Context, rejected, code string) (string, error) {
	if !s.rotating {
		return s.static, nil
	}
	if rejected == "" {
		if p := s.usable.Load(); p != nil && !p.expiredAt(s.now()) {
			return p.Access, nil
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.publish()

	if err := s.prepare(ctx); err != nil {
		return "", err
	}
	if rejected != "" {
		return s.replaceRejected(ctx, rejected, code)
	}
	if s.cur.Access != "" && !s.expired() && !s.cur.Dead {
		return s.cur.Access, nil
	}
	if s.cur.Dead && s.cur.issued() && s.proofPending {
		// The budget for an early exchange depends on the proof.
		s.loadProof(ctx)
		if s.proofPending {
			return "", errors.New("Slack rejected the app-level token and its stored state could not be read; retrying")
		}
	}
	if s.awaitingRecovery() {
		return "", s.awaitingRecoveryError()
	}
	// No usable token: renew now rather than offer Slack a dead one.
	if s.renewErr != nil {
		s.terminal = s.renewErr
		return "", s.terminal
	}
	if err := s.refresh(ctx, s.deadBudget()); err != nil {
		s.noteRenewFailure(err)
		return "", s.giveUpIfFinal(err)
	}
	return s.cur.Access, nil
}

// deadBudget is the forced-refresh count a renewal carries: the count
// decided when Slack called the token dead, unless the exchange is the
// scheduled renewal, which starts afresh.
func (s *appTokenSource) deadBudget() int {
	if s.cur.Dead && (!s.cur.issued() || s.beforeSchedule()) {
		return s.cur.NextRetries
	}
	return 0
}

// beforeSchedule reports whether the current token is not yet due for its
// scheduled renewal.
func (s *appTokenSource) beforeSchedule() bool {
	return s.now().Add(refreshMargin).Before(s.cur.ExpiresAt)
}

// Load reads the stored chain and publishes its token without any exchange,
// so the first connection never waits on a renewal.
func (s *appTokenSource) Load(ctx context.Context) {
	if !s.rotating {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.publish()
	_ = s.prepare(ctx)
}

// Renew exchanges the token ahead of its expiry, or right away for a pasted
// token whose expiry is unknown. The renewal worker calls it.
func (s *appTokenSource) Renew(ctx context.Context) {
	if !s.rotating {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.publish()
	if s.prepare(ctx) != nil || !s.renewDue() {
		return
	}
	// Let reconnects use the current token while the exchange runs.
	s.publish()
	// A scheduled renewal starts a fresh forced-refresh budget: the current
	// token may have been accepted before its proof landed.
	if err := s.refresh(ctx, s.deadBudget()); err != nil {
		s.noteRenewFailure(err)
	}
}

// prepare loads state and flushes pending saves, then reports a terminal
// state. Called with mu held.
func (s *appTokenSource) prepare(ctx context.Context) error {
	if !s.loaded {
		if err := s.load(ctx); err != nil {
			return err
		}
		s.loaded = true
	}
	s.foldProof()
	// Before any early return: a pending pair may hold the only live
	// refresh token.
	if s.unsaved || s.metaUnsaved {
		// One attempt here, so a stalled vault holds the lock briefly;
		// the next call tries again.
		_ = s.persist(ctx, 1)
	}
	if s.foreignPending != nil && s.saveForeign(ctx, *s.foreignPending) == nil && s.foreignMsg != "" {
		saved := &terminalRefreshError{s.foreignMsg + " Slack replaced that token's refresh token; the successor is kept in the plugin's secrets as " + foreignSecretPrefix + s.seed + "."}
		// Only the message changes; whether the source can still serve
		// the current access token does not.
		if s.terminal != nil {
			s.terminal = saved
		}
		if s.renewErr != nil {
			s.renewErr = saved
		}
	}
	return s.terminal
}

// publish refreshes the lock-free snapshots read by Token and Warning.
// Called with mu held.
func (s *appTokenSource) publish() {
	s.publishWarning()
	if !s.loaded || s.terminal != nil || s.cur.Access == "" || s.cur.Dead {
		s.usable.Store(nil)
		return
	}
	p := s.cur
	s.usable.Store(&p)
}

// expiredAt reports whether a token Slack issued has passed its expiry.
func (p rotatingPair) expiredAt(now time.Time) bool {
	return p.issued() && !now.Before(p.ExpiresAt)
}

// replaceRejected handles a token Slack refused.
func (s *appTokenSource) replaceRejected(ctx context.Context, rejected, code string) (string, error) {
	// Proof only matters here, so it is read here rather than on every
	// lookup; a failed read is retried on the next rejection.
	s.loadProof(ctx)
	if rejected != s.cur.Access {
		// A renewal already replaced it while Slack was answering.
		return s.cur.Access, nil
	}
	if s.proofPending && s.cur.issued() {
		// Without the proof the retry budget is unknown; never decide on
		// it. A token Slack called dead is still never resent.
		if code == "token_expired" || code == "token_revoked" {
			s.markDead(ctx, s.cur.Retries+1, code)
		}
		return "", errors.New("Slack rejected the app-level token and its stored state could not be read; retrying")
	}
	if s.cur.issued() && s.beforeSchedule() && !(s.cur.Proven && (code == "token_expired" || s.expired())) {
		// Slack rejected a token it issued, and not because a proven token
		// reached its expiry: it never opened a socket, or it was refused
		// within its lifetime. One refresh is allowed per chain link, and
		// the count travels with the pair, so a replacement Slack also
		// refuses spends nothing at once. After that the reconnect backoff
		// retries the same token, which recovers from causes such as an IP
		// allowlist, and renewal still runs on schedule. Once the scheduled
		// renewal is due, the refresh below is that renewal, on a fresh
		// budget, whichever of the worker or a reconnect gets there first.
		explicit := code == "token_expired" || code == "token_revoked"
		if s.renewErr != nil {
			if explicit {
				// Slack named the token dead and no renewal can succeed.
				s.markDead(ctx, s.cur.Retries+1, code)
				s.terminal = s.renewErr
				return "", s.terminal
			}
			// Keep the actionable cause instead of generic advice.
			return "", fmt.Errorf("Slack rejected the app-level token (%s) and it cannot be renewed: %w", code, s.renewErr)
		}
		if s.cur.Retries < maxForcedRefreshes {
			if err := s.refresh(ctx, s.cur.Retries+1); err != nil {
				// Not terminal: the rejection may be temporary, so the
				// current token keeps being retried until it expires.
				s.noteRenewFailure(err)
				if explicit {
					// Slack called this token dead: stop offering it and
					// make this same forced refresh once the cooldown passes.
					s.markDead(ctx, s.cur.Retries+1, code)
				}
				if explicit && s.renewErr != nil {
					s.terminal = s.renewErr
					return "", s.terminal
				}
				return "", err
			}
			return s.cur.Access, nil
		}
		if explicit {
			// Slack called this replacement dead too. Its proof may only
			// have failed to save, so the chain is not given up, but the
			// next exchange waits a delay that grows with every token
			// Slack calls dead this way (recoveryAt).
			s.markDead(ctx, s.cur.Retries+1, code)
			return "", s.awaitingRecoveryError()
		}
		return "", fmt.Errorf("Slack rejected an app-level token it issued and that has not expired (%s) — check the app's IP allowlist and that it is still installed", code)
	}
	if s.renewErr != nil {
		// No refresh is possible. Stop only when Slack said the token is
		// gone for good; an ambiguous rejection (an IP allowlist, say) is
		// retried with the same token by the reconnect backoff.
		if code == "token_expired" || code == "token_revoked" || s.expired() {
			if code == "token_expired" || code == "token_revoked" {
				s.markDead(ctx, 0, code)
			}
			s.terminal = s.renewErr
			return "", s.terminal
		}
		return "", fmt.Errorf("Slack rejected the app-level token (%s) and it cannot be renewed: %w", code, s.renewErr)
	}
	if err := s.refresh(ctx, 0); err != nil {
		s.noteRenewFailure(err)
		// Give up only when this token is known dead; after an ambiguous
		// rejection it is retried, as when the worker hit the failure first.
		if code == "token_expired" || code == "token_revoked" || s.expired() {
			if code == "token_expired" || code == "token_revoked" {
				// This was a scheduled-budget refresh; keep it that way.
				s.markDead(ctx, 0, code)
			}
			return "", s.giveUpIfFinal(err)
		}
		return "", err
	}
	return s.cur.Access, nil
}

// markDead stops offering the current token. next is the forced-refresh
// count the exchange replacing it carries, stored so neither a cooldown nor
// a restart changes it.
func (s *appTokenSource) markDead(ctx context.Context, next int, code string) {
	s.cur.Dead, s.cur.NextRetries, s.cur.DeadCode, s.cur.DeadAt = true, next, code, s.now()
	s.saveMeta(ctx)
}

// saveMeta stores bookkeeping on the current pair, retrying later on failure.
func (s *appTokenSource) saveMeta(ctx context.Context) {
	if s.persist(ctx, 1) != nil {
		s.metaUnsaved = true
	}
}

// recoveryDelay is how long a dead token whose forced-refresh budget is
// spent waits for its exchange. It doubles with each further token Slack
// calls dead that way, and never runs past the scheduled renewal.
const recoveryDelay = 30 * time.Minute

// recoveryAt is when a dead token with a spent budget may be exchanged.
func (s *appTokenSource) recoveryAt() time.Time {
	doublings := min(max(s.cur.NextRetries-maxForcedRefreshes-1, 0), 4)
	at := s.cur.DeadAt.Add(recoveryDelay << doublings)
	if due := s.cur.ExpiresAt.Add(-refreshMargin); due.Before(at) {
		return due
	}
	return at
}

// awaitingRecovery reports a dead token whose forced-refresh budget is
// spent and whose recovery delay has not passed.
func (s *appTokenSource) awaitingRecovery() bool {
	return s.cur.Dead && s.cur.issued() && s.cur.NextRetries > maxForcedRefreshes && s.now().Before(s.recoveryAt())
}

func (s *appTokenSource) awaitingRecoveryError() error {
	return fmt.Errorf("Slack rejected the renewed app-level token as well; the next renewal attempt is at %s — if this repeats, generate a new app-level token and paste its access and refresh tokens", s.recoveryAt().UTC().Format(time.RFC3339))
}

// creditProof recomputes a dead token's pending budget once proof shows
// Slack accepted it, as if the proof had been known at the rejection: an
// accepted token that expired is renewed on a fresh budget, any other
// rejection of it costs the first forced refresh.
func (s *appTokenSource) creditProof() {
	switch {
	case !s.cur.Dead:
	case s.cur.DeadCode == "token_expired":
		s.cur.NextRetries = 0
	default:
		s.cur.NextRetries = 1
	}
}

// Reject records that Slack called token expired or revoked, without an
// exchange, so it is not sent again.
func (s *appTokenSource) Reject(ctx context.Context, token, code string) {
	if !s.rotating || (code != "token_expired" && code != "token_revoked") {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.publish()
	if s.prepare(ctx) == nil && token == s.cur.Access && !s.cur.Dead {
		next := 0
		if s.cur.issued() {
			next = s.cur.Retries + 1
		}
		s.markDead(ctx, next, code)
	}
}

// maxForcedRefreshes bounds refreshes forced by Slack rejecting tokens it
// issued, until one of them opens a socket; later ones wait recoveryAt.
const maxForcedRefreshes = 1

// Confirm records that token opened a socket.
func (s *appTokenSource) Confirm(token string) {
	if s.rotating {
		s.confirmed.Store(&token)
		s.confirms.Add(1)
	}
}

// foldProof applies Confirm to the current pair. Called with mu held.
func (s *appTokenSource) foldProof() {
	p := s.confirmed.Load()
	if p == nil || *p != s.cur.Access {
		return
	}
	// Slack accepted the token again after a failed forced refresh: the
	// "retrying" warning is stale unless a scheduled renewal is due.
	if s.renewErr == nil && s.confirms.Load() > s.failedAt && s.cur.issued() && s.now().Add(refreshMargin).Before(s.cur.ExpiresAt) {
		s.lastRenewErr = ""
	}
	// Acceptance seen live settles what the stored proof would tell.
	s.proofPending = false
	if s.cur.Proven {
		return
	}
	s.cur.Proven, s.cur.Retries = true, 0
	s.creditProof()
	s.proofDirty = s.cur.issued()
}

// SaveProof stores that the current token opened a socket. The write runs
// without mu, so reconnects never wait behind it, and under its own key, so
// it cannot overwrite a newer pair.
func (s *appTokenSource) SaveProof(ctx context.Context) {
	if !s.rotating {
		return
	}
	s.mu.Lock()
	s.foldProof()
	dirty, token := s.proofDirty, s.cur.Access
	s.mu.Unlock()
	if !dirty {
		return
	}
	saveCtx, cancel := context.WithTimeout(ctx, vaultTimeout)
	err := s.store.SetSecret(saveCtx, proofSecretPrefix+s.seed, tokenDigest(token))
	cancel()
	if err != nil {
		log.Printf("slack: save app-level token proof (will retry): %v", err)
		return
	}
	s.mu.Lock()
	if s.cur.Access == token {
		s.proofDirty = false
	}
	s.mu.Unlock()
}

// proofSecretPrefix names the secret holding the digest of the last token
// of a chain that opened a socket.
const proofSecretPrefix = "app_token_proof."

// tokenDigest identifies a token without storing it.
func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:16])
}

// Warning describes a degraded rotation for the status page.
func (s *appTokenSource) Warning() string { return s.WarningBesides("") }

// WarningBesides is Warning without the parts whose cause reported already
// contains, such as a renewal failure the listener reported as its own
// connection error.
func (s *appTokenSource) WarningBesides(reported string) string {
	p := s.warning.Load()
	if p == nil {
		return ""
	}
	var texts []string
	for _, part := range *p {
		if part.cause == "" || !strings.Contains(reported, part.cause) {
			texts = append(texts, part.text)
		}
	}
	return strings.Join(texts, "; ")
}

// warningPart is one sentence of Warning and the error it reports, if any.
type warningPart struct{ text, cause string }

// publishWarning refreshes the Warning() snapshot. Called with mu held.
func (s *appTokenSource) publishWarning() {
	var parts []warningPart
	if s.unsaved && s.saveFailed {
		parts = append(parts, warningPart{text: "the renewed app-level token could not be saved yet; a restart, including saving the plugin settings, before the save succeeds would need a new token"})
	}
	switch {
	case s.renewErr != nil:
		cause := s.renewErr.Error()
		parts = append(parts, warningPart{"the app-level token cannot be renewed: " + cause, cause})
	case s.lastRenewErr != "":
		parts = append(parts, warningPart{"renewing the app-level token failed, retrying: " + s.lastRenewErr, s.lastRenewErr})
	}
	s.warning.Store(&parts)
}

func (s *appTokenSource) secretKey() string { return rotationSecretPrefix + s.seed }

// sameChain reports whether other continues this source's rotation chain —
// the vault identifies a chain by its configured refresh token alone — so a
// listener restart keeps this source and any pair it has not saved yet.
func (s *appTokenSource) sameChain(other *appTokenSource) bool {
	return s.rotating && other.rotating && s.seed == other.seed
}

// adopt takes other's client credentials, which may have changed while the
// chain stayed the same. Failures latched under the old credentials are
// cleared so corrected credentials take effect.
func (s *appTokenSource) adopt(other *appTokenSource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clientID == other.clientID && s.clientSecret == other.clientSecret {
		return
	}
	s.clientID, s.clientSecret = other.clientID, other.clientSecret
	s.renewErr, s.terminal = nil, nil
}

// renewDue reports whether a renewal should be attempted now. The pasted
// access token has no known expiry, so it is exchanged once right away.
func (s *appTokenSource) renewDue() bool {
	if s.renewErr != nil || s.now().Before(s.retryAt) {
		return false
	}
	return !s.cur.issued() || !s.now().Add(refreshMargin).Before(s.cur.ExpiresAt)
}

func (s *appTokenSource) expired() bool {
	return s.cur.issued() && !s.now().Before(s.cur.ExpiresAt)
}

func (s *appTokenSource) noteRenewFailure(err error) {
	var final *terminalRefreshError
	if errors.As(err, &final) {
		s.renewErr = err
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	var paused *cooldownError
	if errors.As(err, &paused) {
		// No exchange happened; the failure that started the cooldown
		// stays the reported cause.
		return
	}
	s.lastRenewErr = err.Error()
	// Only a Confirm after this failure may clear the warning.
	s.failedAt = s.confirms.Load()
	log.Printf("slack: renew app-level token: %v", err)
}

// giveUpIfFinal stops the source when no refresh can ever succeed.
func (s *appTokenSource) giveUpIfFinal(err error) error {
	var final *terminalRefreshError
	if errors.As(err, &final) {
		s.terminal = err
	}
	return err
}

// load picks the stored pair when it descends from the configured refresh
// token, otherwise the configured tokens themselves.
func (s *appTokenSource) load(ctx context.Context) error {
	s.cur = s.initial
	readCtx, cancel := context.WithTimeout(ctx, vaultTimeout)
	defer cancel()
	raw, found, err := s.store.GetSecret(readCtx, s.secretKey())
	if err != nil {
		return fmt.Errorf("read stored app-level token: %w", err)
	}
	if !found {
		_ = s.checkForeign(readCtx)
		return nil
	}
	var stored rotatingPair
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		// The record may hold the only live refresh token, so it is never
		// replaced by the configured, possibly spent, seed pair. The decode
		// error is not echoed: it can quote a misplaced credential.
		return errors.New("the stored app-level token record is unreadable — generate a new app-level token and paste its access and refresh tokens")
	}
	if stored.Seed != s.seed || stored.Refresh == "" {
		// The key is per seed, so this record is damaged; it may still hold
		// the only live refresh token, so it is never overwritten.
		return errors.New("the stored app-level token record is damaged — generate a new app-level token and paste its access and refresh tokens")
	}
	s.cur = stored
	if stored.Refresh == s.initial.Refresh && stored.Access != s.initial.Access {
		// No exchange has succeeded for this seed, so the record is only
		// the preflight copy; an access token pasted since then wins.
		s.cur.Access, s.cur.ExpiresAt, s.cur.Dead = s.initial.Access, s.initial.ExpiresAt, false
	}
	s.retryAt = stored.RetryAt
	s.proofPending = true
	// A quarantined successor of the current refresh token explains why
	// the chain cannot continue.
	_ = s.checkForeign(readCtx)
	return nil
}

// checkForeign looks for a quarantined successor of the current refresh
// token. A failed read does not hold back the loaded access token, which
// needs no exchange; refresh retries the read before spending anything.
// Called with mu held.
func (s *appTokenSource) checkForeign(ctx context.Context) error {
	if err := s.loadForeign(ctx); err != nil {
		s.foreignUnchecked = true
		log.Printf("slack: %v (will retry before the next renewal)", err)
		return err
	}
	s.foreignUnchecked = false
	return nil
}

// refresh spends the current refresh token. No exchange starts once the
// listener is stopping, but one already sent runs to completion on a detached
// context: Slack may have invalidated the old refresh token, so dropping the
// answer or its save would break the chain.
func (s *appTokenSource) refresh(ctx context.Context, retries int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.unsaved {
		// The vault does not hold the current refresh token yet. Spending
		// it now could leave no saved copy of any live refresh token.
		return errors.New("refresh app-level token: waiting for the previous renewal to be saved")
	}
	if wait := s.retryAt.Sub(s.now()); wait > 0 {
		return &cooldownError{wait: wait, cause: s.lastRenewErr}
	}
	if s.foreignUnchecked {
		readCtx, cancel := context.WithTimeout(ctx, vaultTimeout)
		err := s.checkForeign(readCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("refresh app-level token: not attempted, the plugin secrets cannot be read: %w", err)
		}
		if s.renewErr != nil {
			// The configured refresh token was already spent.
			return s.renewErr
		}
	}
	// Prove the vault takes writes before spending the refresh token: once
	// Slack answers, the old token is gone and the answer must be saved.
	if err := s.persist(ctx, 1); err != nil {
		return fmt.Errorf("refresh app-level token: not attempted, the plugin secrets cannot be written: %w", err)
	}
	// The vault write may have outlasted the listener; no new exchange
	// starts once it is stopping.
	if err := ctx.Err(); err != nil {
		return err
	}
	res, err := s.exchange(ctx)
	var unknown *outcomeUnknownError
	if errors.As(err, &unknown) && ctx.Err() == nil {
		// Slack may have spent the refresh token without its answer
		// arriving. A redeemed refresh token keeps working only for a short
		// grace period, so it is replayed once at once rather than after
		// the cooldown. Like any exchange, the replay never starts once the
		// listener is stopping; the saved cooldown then hands the retry to
		// the next process.
		log.Printf("slack: %v; retrying the exchange once", err)
		res, err = s.exchange(ctx)
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), saveTimeout)
	defer cancel()
	if err != nil {
		// Every failed exchange imposes a cooldown shared by reconnects and
		// the renewal worker; Slack's Retry-After wins when it sent one.
		cooldown := refreshCooldown
		var limited *rateLimitedError
		if errors.As(err, &limited) {
			cooldown = limited.after
		}
		s.retryAt = s.now().Add(cooldown)
		// Saved with the pair so a restart (a settings save) honours it.
		s.cur.RetryAt = s.retryAt
		if s.persist(ctx, 1) != nil {
			s.metaUnsaved = true
		}
		var foreign *foreignPairError
		if errors.As(err, &foreign) {
			return s.keepForeignPair(ctx, foreign)
		}
		return err
	}
	expiresIn := time.Duration(expirySeconds(res.ExpiresIn)) * time.Second
	if expiresIn <= 0 {
		expiresIn = 12 * time.Hour
	}
	if res.AccessToken == "" {
		// An app-level successor without a usable access token. Its refresh
		// token continues the chain; the current access token stays in use,
		// since a refresh does not invalidate it. The next exchange waits a
		// cooldown that doubles with each such reply, saved with the pair so
		// a restart keeps it.
		s.cur.Refresh = res.RefreshToken
		s.cur.Incomplete++
		s.retryAt = s.now().Add(refreshCooldown << min(s.cur.Incomplete-1, 7))
		s.cur.RetryAt = s.retryAt
		s.unsaved = true
		_ = s.persist(ctx, saveAttempts)
		return errors.New("refresh app-level token: Slack returned a new refresh token without an access token; the next attempt uses the new refresh token")
	}
	s.lastRenewErr = ""
	// A proof pending for the replaced token must not be credited to the
	// new one, which Slack has not accepted yet.
	s.proofDirty, s.proofPending = false, false
	s.cur = rotatingPair{
		Access:    res.AccessToken,
		Refresh:   res.RefreshToken,
		ExpiresAt: s.now().Add(expiresIn),
		Seed:      s.seed,
		Retries:   retries,
	}
	s.unsaved = true
	_ = s.persist(ctx, saveAttempts)
	return nil
}

// persist saves the current pair. After a refresh a failure is shown as a
// warning rather than failing the refresh: the previous refresh token is
// spent, so the new pair is the only working one and must still be used.
// The save is retried on the next call.
func (s *appTokenSource) persist(ctx context.Context, attempts int) error {
	value, err := json.Marshal(s.cur)
	if err != nil {
		log.Printf("slack: encode refreshed app-level token: %v", err)
		return err
	}
	for attempt := 1; ; attempt++ {
		saveCtx, cancel := context.WithTimeout(ctx, vaultTimeout)
		err = s.store.SetSecret(saveCtx, s.secretKey(), string(value))
		cancel()
		if err == nil {
			s.unsaved, s.saveFailed, s.metaUnsaved = false, false, false
			return nil
		}
		if attempt >= attempts || ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Duration(attempt) * time.Second):
		}
	}
	if s.unsaved {
		s.saveFailed = true
	}
	log.Printf("slack: save app-level token (will retry): %v", err)
	return err
}

// terminalRefreshError is a refresh failure retrying cannot fix.
type terminalRefreshError struct{ msg string }

func (e *terminalRefreshError) Error() string { return e.msg }

// rateLimitedError is Slack asking the plugin to wait before refreshing.
type rateLimitedError struct{ after time.Duration }

func (e *rateLimitedError) Error() string {
	return fmt.Sprintf("refresh app-level token: rate limited by Slack for %s", e.after)
}

// outcomeUnknownError is a failed exchange that Slack may have carried out:
// the request was possibly sent, but no usable answer came back.
type outcomeUnknownError struct{ msg string }

func (e *outcomeUnknownError) Error() string { return e.msg }

// exchange sends the current refresh token to Slack. It runs detached from
// the listener with its own deadline, as does the save that follows, so a
// slow Slack answer cannot eat the time needed to store the successor.
// Called with mu held.
func (s *appTokenSource) exchange(ctx context.Context) (*refreshResponse, error) {
	exchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), exchangeTimeout)
	defer cancel()
	return refreshAppToken(exchCtx, s.clientID, s.clientSecret, s.cur.Refresh)
}

// refreshResponse is oauth.v2.access's reply to a refresh_token grant. Each
// field is decoded on its own (decodeRefreshResponse): once Slack has sent a
// successor the old refresh token is spent, so a malformed neighbouring
// field must never discard it.
type refreshResponse struct {
	OK           bool
	Error        string
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    json.RawMessage
}

// appLevelTokenType is the token_type Slack documents for a refreshed
// app-level token.
const appLevelTokenType = "app_level"

func decodeRefreshResponse(fields map[string]json.RawMessage) refreshResponse {
	var ok bool
	_ = json.Unmarshal(fields["ok"], &ok)
	return refreshResponse{
		OK:           ok,
		Error:        jsonString(fields["error"]),
		AccessToken:  jsonString(fields["access_token"]),
		RefreshToken: jsonString(fields["refresh_token"]),
		TokenType:    jsonString(fields["token_type"]),
		ExpiresIn:    fields["expires_in"],
	}
}

// jsonString returns raw as a string, or "" when it is not a JSON string.
func jsonString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// decodeFields reads a JSON object's top-level fields in order. On a read or
// syntax error it returns the fields completed before it alongside the error,
// so a truncated body keeps what arrived whole.
func decodeFields(r io.Reader) (map[string]json.RawMessage, error) {
	// The decoder finishes a value that ends the input (a string's closing
	// quote needs a lookahead byte) only on io.EOF, so any other read error,
	// such as a body shorter than its Content-Length, is presented to it as
	// io.EOF and reported afterwards.
	body := &eofReader{r: r}
	fields, err := decodeObject(json.NewDecoder(body))
	if body.err != nil {
		return fields, body.err
	}
	return fields, err
}

func decodeObject(dec *json.Decoder) (map[string]json.RawMessage, error) {
	fields := map[string]json.RawMessage{}
	tok, err := dec.Token()
	if err != nil {
		return fields, err
	}
	if tok != json.Delim('{') {
		return fields, errors.New("not a JSON object")
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fields, err
		}
		key, _ := tok.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return fields, err
		}
		fields[key] = value
	}
	// The closing brace; nothing after it is read.
	_, err = dec.Token()
	return fields, err
}

// eofReader turns every read error into io.EOF, keeping the first one.
type eofReader struct {
	r   io.Reader
	err error
}

func (e *eofReader) Read(p []byte) (int, error) {
	if e.err != nil {
		return 0, io.EOF
	}
	n, err := e.r.Read(p)
	if err != nil && err != io.EOF {
		e.err = err
		err = io.EOF
	}
	return n, err
}

// refreshAppToken exchanges a refresh token for a new pair. The call is
// authenticated by the client credentials in the body, not a bearer token.
// Error messages carry only status codes and Slack error identifiers, never
// response bodies, since those could echo credentials.
func refreshAppToken(ctx context.Context, clientID, clientSecret, refreshToken string) (*refreshResponse, error) {
	if refreshToken == "" {
		return nil, &terminalRefreshError{"refresh app-level token: no refresh token available — paste the refresh token shown next to the app-level token"}
	}
	form := url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		slackAPIBase+"/oauth.v2.access", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	// The body carries the client secret and a single-use refresh token, so
	// a redirect is never followed: it would replay both to another URL.
	noRedirect := &http.Client{
		Timeout:       requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		// The client's error can quote URLs and headers from a redirect;
		// only its kind is reported. Slack may have spent the refresh token
		// before the failure, so the outcome is unknown.
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, &outcomeUnknownError{"refresh app-level token: the request to Slack timed out"}
		}
		return nil, &outcomeUnknownError{"refresh app-level token: the request to Slack failed"}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, &rateLimitedError{after: retryAfter(resp)}
	}
	if resp.StatusCode >= 500 {
		// A gateway error can come after Slack redeemed the token.
		return nil, &outcomeUnknownError{fmt.Sprintf("refresh app-level token: HTTP status %d", resp.StatusCode)}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("refresh app-level token: HTTP status %d", resp.StatusCode)
	}
	// Read the fields one at a time, without waiting for a clean end of the
	// body: once Slack has sent the new pair the old refresh token is spent,
	// so a connection dropped after the object, or inside it after the
	// successor arrived, must not discard it.
	fields, err := decodeFields(io.LimitReader(resp.Body, maxResponseBytes))
	out := decodeRefreshResponse(fields)
	if err != nil && out.RefreshToken == "" {
		return nil, &outcomeUnknownError{"refresh app-level token: Slack returned an unreadable response"}
	}
	// A successor refresh token means Slack spent the old one, whatever
	// the rest of the reply says or failed to say.
	if !out.OK && out.RefreshToken == "" {
		if out.Error == "ratelimited" {
			return nil, &rateLimitedError{after: retryAfter(resp)}
		}
		return nil, refreshFailure(out.Error)
	}
	if out.AccessToken == "" && out.RefreshToken != "" {
		if out.TokenType == appLevelTokenType {
			// Slack spent the old refresh token and named the successor
			// app-level, so it continues this chain even without a usable
			// access token; the caller exchanges it again.
			return &out, nil
		}
		// Slack spent the old refresh token; keep the successor, but never
		// use it: its token kind is unknown.
		return nil, &foreignPairError{
			terminalRefreshError: terminalRefreshError{"refresh app-level token: Slack returned a refresh token without an access token. Generate a new app-level token and paste its access and refresh tokens."},
			pair:                 rotatingPair{Refresh: out.RefreshToken},
		}
	}
	if out.AccessToken == "" || out.RefreshToken == "" {
		return nil, errors.New("refresh app-level token: Slack returned no token pair")
	}
	if !strings.HasPrefix(out.AccessToken, rotatingAppTokenPrefix) && !strings.HasPrefix(out.AccessToken, appTokenPrefix) {
		// The refresh token belonged to another token kind, most likely the
		// bot token. Slack has spent it, so the successor is handed back for
		// safekeeping, but never used: it cannot open a socket.
		return nil, &foreignPairError{
			terminalRefreshError: terminalRefreshError{"refresh app-level token: the refresh token belongs to a different token (" + describeToken(out.AccessToken) + "). Paste the refresh token generated with the app-level token under Basic Information > App-Level Tokens."},
			pair:                 rotatingPair{Access: out.AccessToken, Refresh: out.RefreshToken},
		}
	}
	return &out, nil
}

// refreshFailure maps oauth.v2.access error codes. Only codes listed here are
// echoed: anything else in the error field could be an echoed credential.
func refreshFailure(code string) error {
	switch code {
	case "invalid_grant_type":
		return &terminalRefreshError{"refresh app-level token: invalid_grant_type — Slack refused the refresh request itself; this is a plugin bug, please report it."}
	case "invalid_refresh_token", "bad_refresh_token", "token_revoked", "token_expired":
		// The only token this call carries is the refresh token, so Slack's
		// token_revoked/token_expired name it; resending it cannot succeed.
		return &terminalRefreshError{"refresh app-level token: " + code + " — the refresh token was already used, revoked or expired. Generate a new app-level token and paste both its access and refresh tokens."}
	case "invalid_client_id", "bad_client_secret":
		return &terminalRefreshError{"refresh app-level token: " + code + " — check the Client ID and Client Secret from Basic Information > App Credentials."}
	case "invalid_auth":
		return errors.New("refresh app-level token: invalid_auth — Slack could not validate the request; check the Client ID and Client Secret from Basic Information > App Credentials and that the app's IP allowlist admits this host")
	case "internal_error", "fatal_error":
		// Slack documents that part of the operation may have succeeded,
		// so the refresh token may be redeemed already.
		return &outcomeUnknownError{"refresh app-level token: " + code}
	case "ratelimited", "request_timeout", "service_unavailable", "invalid_arguments", "invalid_form_data",
		// The rest of oauth.v2.access's documented error codes.
		"access_denied", "accesslimited", "account_inactive", "deprecated_endpoint", "ekm_access_denied", "enterprise_is_restricted",
		"invalid_arg_name", "invalid_array_arg", "invalid_charset", "invalid_post_type", "method_deprecated", "missing_argument",
		"missing_post_type", "not_allowed_token_type", "not_authed", "org_login_required", "team_access_not_granted",
		"team_added_to_org", "two_factor_setup_required":
		return errors.New("refresh app-level token: " + code)
	default:
		return errors.New("refresh app-level token: Slack returned an unrecognized error")
	}
}

// foreignSecretPrefix names the secret keeping a successor pair of another
// token kind, returned when the operator pasted, say, the bot's refresh token.
// Slack spent the pasted token, so dropping its successor would break that
// other chain; it is kept apart from the Socket Mode pair and never used.
const foreignSecretPrefix = "foreign_token_rotation."

// foreignPairError is a refresh that returned a pair of another token kind.
type foreignPairError struct {
	terminalRefreshError
	pair rotatingPair
}

func (e *foreignPairError) Unwrap() error { return &e.terminalRefreshError }

// keepForeignPair stores a foreign successor pair and returns the terminal
// error. A failed save is retried on later calls, as for the app's own pair.
// Called with mu held.
func (s *appTokenSource) keepForeignPair(ctx context.Context, foreign *foreignPairError) error {
	pair := foreign.pair
	pair.Seed = s.seed
	pair.Reason = foreign.msg
	pair.Replaced = tokenDigest(s.cur.Refresh)
	s.foreignMsg = foreign.msg
	if err := s.saveForeign(ctx, pair); err != nil {
		return &terminalRefreshError{foreign.msg + " Slack replaced that token's refresh token; saving its successor failed and is being retried (see the plugin log)."}
	}
	return &terminalRefreshError{foreign.msg + " Slack replaced that token's refresh token; the successor is kept in the plugin's secrets as " + foreignSecretPrefix + s.seed + "."}
}

// loadForeign restores, after a restart, the diagnosis for a seed whose
// refresh token turned out to belong to another token kind. The saved
// successor is never used.
func (s *appTokenSource) loadForeign(ctx context.Context) error {
	raw, found, err := s.store.GetSecret(ctx, foreignSecretPrefix+s.seed)
	if err != nil {
		return fmt.Errorf("read quarantined token record %s%s: %w", foreignSecretPrefix, s.seed, err)
	}
	if !found {
		return nil
	}
	var kept rotatingPair
	if err := json.Unmarshal([]byte(raw), &kept); err != nil || kept.Refresh == "" {
		// Not provably a successor: never stop a chain on it, and leave
		// the record for the operator.
		log.Printf("slack: ignoring unreadable quarantined app-level token record %s%s", foreignSecretPrefix, s.seed)
		return nil
	}
	if kept.Replaced != tokenDigest(s.cur.Refresh) {
		// It replaced another link of the chain, not the current one.
		return nil
	}
	s.foreignMsg = kept.Reason
	if s.foreignMsg == "" {
		s.foreignMsg = "refresh app-level token: Slack's reply to an earlier refresh could not be used."
	}
	s.renewErr = &terminalRefreshError{s.foreignMsg + " Slack replaced that token's refresh token; the successor is kept in the plugin's secrets as " + foreignSecretPrefix + s.seed + "."}
	return nil
}

// cooldownError reports a refresh deferred by the cooldown; it is not a new
// failure.
type cooldownError struct {
	wait  time.Duration
	cause string
}

func (e *cooldownError) Error() string {
	msg := "refresh app-level token: paused after a failed attempt or Slack rate limit, retrying in " + e.wait.Round(time.Second).String()
	if e.cause != "" {
		msg += " (last failure: " + e.cause + ")"
	}
	return msg
}

// expirySeconds reads expires_in as a number or numeric string; anything
// else yields 0, which selects the 12-hour default.
func expirySeconds(raw json.RawMessage) int {
	var n float64
	if json.Unmarshal(raw, &n) == nil {
		return int(n)
	}
	var str string
	if json.Unmarshal(raw, &str) == nil {
		if v, err := strconv.Atoi(str); err == nil {
			return v
		}
	}
	return 0
}

// saveForeign writes a foreign successor pair, keeping it pending on failure.
func (s *appTokenSource) saveForeign(ctx context.Context, pair rotatingPair) error {
	value, err := json.Marshal(pair)
	if err == nil {
		saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), vaultTimeout)
		err = s.store.SetSecret(saveCtx, foreignSecretPrefix+s.seed, string(value))
		cancel()
	}
	if err != nil {
		s.foreignPending = &pair
		log.Printf("slack: keep successor of a foreign refresh token (will retry): %v", err)
		return err
	}
	s.foreignPending = nil
	return nil
}

// retryAfter reads Slack's Retry-After header, defaulting when absent.
func retryAfter(resp *http.Response) time.Duration {
	if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return defaultRetryAfter
}

// loadProof reads whether the stored token already opened a socket. A failed
// read is retried on later calls, so a vault hiccup at start cannot hide the
// proof and its reset forced-refresh budget. Called with mu held.
func (s *appTokenSource) loadProof(ctx context.Context) {
	if !s.proofPending {
		return
	}
	readCtx, cancel := context.WithTimeout(ctx, vaultTimeout)
	defer cancel()
	proof, found, err := s.store.GetSecret(readCtx, proofSecretPrefix+s.seed)
	if err != nil {
		log.Printf("slack: read app-level token proof (will retry): %v", err)
		return
	}
	s.proofPending = false
	if found && proof == tokenDigest(s.cur.Access) {
		s.cur.Proven, s.cur.Retries = true, 0
		s.creditProof()
	}
}
