package main

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// authMode is how the plugin reaches Slack. It is derived from which
// credentials the operator filled in rather than configured separately: Slack
// token prefixes are unambiguous, and a mode picker only creates a second
// source of truth that can disagree with the pasted credential.
type authMode string

const (
	// authModeApp is a real Slack app running in Socket Mode: an app-level
	// token opens a WebSocket to Slack and a bot token does the reading and
	// writing. This is what a Slack integration normally looks like — events
	// arrive the instant they happen, there is nothing to poll, and no public
	// URL is required, which matters because kandev usually runs on localhost.
	authModeApp authMode = "app"

	// authModeSession is the browser-session fallback: the xoxc- token and `d`
	// cookie the Slack web client uses. Unofficial and unsupported by Slack,
	// and it cannot receive events, so it polls search.messages. It exists for
	// locked-down workspaces where admins do not permit app installs at all —
	// the case the in-tree integration was originally built for.
	authModeSession authMode = "session"
)

// String renders the mode for status output and error messages.
func (m authMode) String() string { return string(m) }

// Label is the human-facing name shown on the plugin page.
func (m authMode) Label() string {
	switch m {
	case authModeApp:
		return "Slack app (Socket Mode)"
	case authModeSession:
		return "Browser session (fallback)"
	default:
		return string(m)
	}
}

// realtime reports whether the mode receives events pushed by Slack. Only the
// session fallback has to poll.
func (m authMode) realtime() bool { return m == authModeApp }

// Defaults mirror the values declared in manifest.yaml's config_schema. They
// are repeated here because GetConfig returns the stored config, and a field
// the operator never touched is absent rather than defaulted.
const (
	defaultCommandPrefix       = "!kandev"
	defaultPollIntervalSeconds = 30
	minPollIntervalSeconds     = 5
	maxPollIntervalSeconds     = 600
)

// config is the validated view of the operator's plugin configuration.
type config struct {
	Mode authMode

	// AppToken (xapp-, or xoxe.xapp- when token rotation is on) opens the
	// Socket Mode WebSocket; BotToken (xoxb-) is used for every Web API call
	// and is the identity replies come from.
	AppToken string
	BotToken string

	// AppRefreshToken (xoxe-) with ClientID and ClientSecret lets the plugin
	// renew an app-level token from a Slack app with token rotation enabled.
	AppRefreshToken string
	ClientID        string
	ClientSecret    string

	// SessionToken (xoxc-) and SessionCookie (`d`) are the fallback pair.
	SessionToken  string
	SessionCookie string

	// CommandPrefix, Channels and PollInterval only apply to the session
	// fallback. A Slack app is addressed by mentioning it or by its slash
	// command, so it needs no prefix, and it is pushed events for the channels
	// it belongs to, so it needs no channel list or cadence.
	CommandPrefix string
	Channels      []string
	PollInterval  time.Duration

	StartAgent   bool
	UtilityAgent string
}

// WebCredentials returns the (token, cookie) pair for Slack Web API calls.
// A bot token authenticates on its own, so no cookie travels with it —
// sending one alongside an xoxb- token makes Slack reject the call rather
// than ignore the extra header.
func (c *config) WebCredentials() (string, string) {
	if c.Mode == authModeApp {
		return c.BotToken, ""
	}
	return c.SessionToken, c.SessionCookie
}

// errNotConfigured is the sentinel for "the operator has not finished filling
// in Settings > Plugins yet". Callers treat it as an idle state, not a failure
// worth logging on every tick.
var errNotConfigured = errors.New("slack plugin is not configured")

// loadConfig validates the raw config_schema values Host.GetConfig returns.
// kandev already enforces required-ness and types; what is left here is the
// cross-field logic a JSON-Schema subset cannot express — which credential
// combinations form a coherent install path.
func loadConfig(raw map[string]any) (*config, error) {
	cfg := &config{
		AppToken:        strings.TrimSpace(configString(raw, "app_token")),
		BotToken:        strings.TrimSpace(configString(raw, "bot_token")),
		AppRefreshToken: strings.TrimSpace(configString(raw, "app_refresh_token")),
		ClientID:        strings.TrimSpace(configString(raw, "client_id")),
		ClientSecret:    strings.TrimSpace(configString(raw, "client_secret")),
		SessionToken:    strings.TrimSpace(configString(raw, "session_token")),
		SessionCookie:   strings.TrimSpace(configString(raw, "session_cookie")),
		CommandPrefix:   strings.TrimSpace(configString(raw, "command_prefix")),
		Channels:        parseChannels(configString(raw, "channels")),
		PollInterval:    pollInterval(raw),
		StartAgent:      configBool(raw, "start_agent"),
		UtilityAgent:    strings.TrimSpace(configString(raw, "utility_agent")),
	}
	if cfg.CommandPrefix == "" {
		cfg.CommandPrefix = defaultCommandPrefix
	}
	mode, err := detectMode(cfg)
	if err != nil {
		return nil, err
	}
	cfg.Mode = mode
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// detectMode picks the install path from the credentials present. The app path
// wins when both are filled: it is the supported one, and silently preferring
// the fallback because a stale cookie is still saved would be a confusing way
// to lose real-time events.
func detectMode(cfg *config) (authMode, error) {
	hasSession := cfg.SessionToken != "" || cfg.SessionCookie != ""
	// A refresh token alone selects the app (it can bootstrap the access
	// token) only when no fallback field is filled; otherwise it is a
	// leftover and the fallback's own validation names what is missing.
	hasApp := cfg.AppToken != "" || cfg.BotToken != "" || (cfg.AppRefreshToken != "" && !hasSession)
	switch {
	case hasApp:
		return authModeApp, nil
	case hasSession:
		return authModeSession, nil
	default:
		return "", errNotConfigured
	}
}

func (c *config) validate() error {
	if c.UtilityAgent == "" {
		return errors.New("pick a triage agent")
	}
	if c.Mode == authModeApp {
		return c.validateApp()
	}
	return c.validateSession()
}

// validateApp checks the Socket Mode pair. Both tokens are required and they
// are easy to swap, so a wrong-prefix value is named rather than left to fail
// as an opaque Slack rejection later.
func (c *config) validateApp() error {
	if c.AppToken == "" && c.AppRefreshToken == "" {
		return errors.New("a Slack app needs its app-level token too — create one with the connections:write scope under Basic Information > App-Level Tokens")
	}
	if c.BotToken == "" {
		return errors.New("a Slack app needs its bot token too — copy the Bot User OAuth Token from OAuth & Permissions after installing the app")
	}
	if c.AppToken != "" && !strings.HasPrefix(c.AppToken, appTokenPrefix) && !strings.HasPrefix(c.AppToken, rotatingAppTokenPrefix) {
		return fmt.Errorf("the app-level token must start with %q (or %q when token rotation is on) — %s", appTokenPrefix, rotatingAppTokenPrefix, describeToken(c.AppToken))
	}
	if strings.HasPrefix(c.BotToken, rotatingBotTokenPrefix) {
		return errors.New("this bot token rotates, which the plugin does not support — paste a static xoxb- Bot User OAuth Token. Token rotation cannot be turned off for an app, so an app that only issues rotating bot tokens needs replacing with one created without rotation")
	}
	if !strings.HasPrefix(c.BotToken, botTokenPrefix) {
		return fmt.Errorf("the bot token must start with %q — %s", botTokenPrefix, describeToken(c.BotToken))
	}
	return c.validateRotation()
}

// rotatesAppToken reports whether the app-level token comes from a Slack app
// with token rotation on. A static xapp- token always wins: leftover rotation
// fields from an earlier setup must not resurrect a stored rotating chain.
func (c *config) rotatesAppToken() bool {
	if strings.HasPrefix(c.AppToken, appTokenPrefix) {
		return false
	}
	return strings.HasPrefix(c.AppToken, rotatingAppTokenPrefix) || c.AppRefreshToken != ""
}

// validateRotation checks the token-rotation fields. A rotating access token
// expires within 12 hours, so it is only usable together with its refresh
// token and the client credentials that authorize the refresh.
func (c *config) validateRotation() error {
	if !c.rotatesAppToken() {
		return nil
	}
	if c.AppRefreshToken == "" {
		return errors.New("this app-level token rotates and expires — also paste its refresh token (xoxe-1-…), shown next to it when it was generated, plus the Client ID and Client Secret from Basic Information")
	}
	if !strings.HasPrefix(c.AppRefreshToken, refreshTokenPrefix) {
		return fmt.Errorf("the app-level refresh token must start with %q — %s", refreshTokenPrefix, describeToken(c.AppRefreshToken))
	}
	if c.ClientID == "" || c.ClientSecret == "" {
		return errors.New("refreshing a rotating app-level token needs the app's Client ID and Client Secret from Basic Information > App Credentials")
	}
	if !clientIDPattern.MatchString(c.ClientID) {
		// Client ID is not a secret field, and the host stores the settings
		// before the plugin reads them, so a credential pasted into it is
		// already saved in plain text; this can only tell the operator to
		// replace it.
		if clientSecretPattern.MatchString(c.ClientID) {
			return errors.New("the Client ID looks like the Client Secret — the Client ID is the dotted number above it under Basic Information > App Credentials; also regenerate the Client Secret there, since this one was saved in a non-secret field")
		}
		if kind := describeToken(c.ClientID); kind != notASlackToken {
			return errors.New("the Client ID field holds a Slack token (" + kind + ") — it was saved in a non-secret field, so revoke or regenerate that token, and enter the dotted Client ID from Basic Information > App Credentials instead")
		}
		return errors.New("the Client ID must be the dotted number (such as 1234567890.1234567890) from Basic Information > App Credentials")
	}
	return nil
}

var (
	// clientIDPattern matches a Slack app's Client ID.
	clientIDPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)
	// clientSecretPattern matches a Slack app's Client Secret.
	clientSecretPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

func (c *config) validateSession() error {
	if c.SessionToken == "" {
		return errors.New("the browser-session fallback needs the xoxc- token as well as the cookie")
	}
	if c.SessionCookie == "" {
		return errors.New("the browser-session fallback needs the `d` cookie as well as the token — copy both from the same logged-in Slack tab")
	}
	if !strings.HasPrefix(c.SessionToken, sessionTokenPrefix) {
		return fmt.Errorf("the browser-session token must start with %q — %s", sessionTokenPrefix, describeToken(c.SessionToken))
	}
	if strings.HasPrefix(c.CommandPrefix, "/") {
		return errors.New("command prefix cannot start with \"/\" — Slack intercepts slash commands before they become messages")
	}
	return nil
}

// Slack's documented token prefixes. Kept as constants because the same
// strings appear in validation, detection, and operator-facing errors.
const (
	appTokenPrefix          = "xapp-"
	rotatingAppTokenPrefix  = "xoxe.xapp-"
	botTokenPrefix          = "xoxb-"
	rotatingBotTokenPrefix  = "xoxe.xoxb-"
	userTokenPrefix         = "xoxp-"
	rotatingUserTokenPrefix = "xoxe.xoxp-"
	sessionTokenPrefix      = "xoxc-"
	refreshTokenPrefix      = "xoxe-"
)

// notASlackToken is describeToken's answer for a value with no Slack prefix.
const notASlackToken = "this does not look like a Slack token"

// describeToken names what the operator actually pasted. Every one of these is
// reachable from the same Slack app page as the token that was wanted, so
// saying which one it is saves a round of guessing.
func describeToken(token string) string {
	switch {
	case strings.HasPrefix(token, appTokenPrefix):
		return "this is an app-level token"
	case strings.HasPrefix(token, rotatingAppTokenPrefix):
		return "this is a rotating app-level access token"
	case strings.HasPrefix(token, botTokenPrefix):
		return "this is a bot token"
	case strings.HasPrefix(token, rotatingBotTokenPrefix):
		return "this is a rotating bot token"
	case strings.HasPrefix(token, userTokenPrefix):
		return "this is a user token; this plugin uses the bot token instead"
	case strings.HasPrefix(token, rotatingUserTokenPrefix):
		return "this is a rotating user token; this plugin uses the bot token instead"
	case strings.HasPrefix(token, sessionTokenPrefix):
		return "this is a browser-session token; it belongs in the fallback fields"
	case strings.HasPrefix(token, refreshTokenPrefix):
		return "this is a refresh token, not an access token"
	default:
		return notASlackToken
	}
}

// parseChannels splits the comma-separated channel list, tolerating the spaces
// and #-prefixes operators paste in. Channel *names* cannot be resolved
// without an extra API round-trip per poll, so only IDs are accepted; a stray
// "#" is stripped rather than silently producing a channel that never matches.
func parseChannels(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == ' ' || r == '\t'
	})
	out := make([]string, 0, len(fields))
	seen := make(map[string]bool, len(fields))
	for _, f := range fields {
		id := strings.TrimPrefix(strings.TrimSpace(f), "#")
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// pollInterval clamps the configured cadence into the supported band.
// Out-of-range values fall back to the default rather than erroring: a
// too-eager interval is a tuning mistake, not a reason to stop triaging.
func pollInterval(raw map[string]any) time.Duration {
	seconds := configInt(raw, "poll_interval_seconds")
	if seconds < minPollIntervalSeconds || seconds > maxPollIntervalSeconds {
		seconds = defaultPollIntervalSeconds
	}
	return time.Duration(seconds) * time.Second
}

func configString(raw map[string]any, key string) string {
	if raw == nil {
		return ""
	}
	s, _ := raw[key].(string)
	return s
}

func configBool(raw map[string]any, key string) bool {
	if raw == nil {
		return false
	}
	b, _ := raw[key].(bool)
	return b
}

// configInt reads a numeric config value. Numbers cross the Host gRPC boundary
// as protobuf Struct values, which are always float64 on arrival — the integer
// cases are for direct construction in tests.
func configInt(raw map[string]any, key string) int {
	if raw == nil {
		return 0
	}
	switch v := raw[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	default:
		return 0
	}
}
