package digestauth

import (
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

type DigestAuth struct {
	Next     httpserver.Handler
	SiteRoot string
	Rules    []Rule
}

func (a DigestAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	var hasAuth bool
	var isAuthenticated bool

	for _, rule := range a.Rules {
		for _, res := range rule.Resources {
			if !httpserver.Path(r.URL.Path).Matches(res) {
				continue
			}

			// Path matches; parse auth header
			username, password, ok := r.BasicAuth()
			hasAuth = true

			// Check credentials
			if !ok ||
				username != rule.Username ||
				!rule.Password(password) {
				continue
			}

			// Flag set only on successful authentication
			isAuthenticated = true
		}
	}

	if hasAuth {
		if !isAuthenticated {
			w.Header().Set("WWW-Authenticate", "Basic")
			return http.StatusUnauthorized, nil
		}
		// "It's an older code, sir, but it checks out. I was about to clear them."
		return a.Next.ServeHTTP(w, r)
	}

	// Pass-thru when no paths match
	return a.Next.ServeHTTP(w, r)
}

type Rule struct {
	Username  string
	Password  func(string) bool
	Resources []string
}
