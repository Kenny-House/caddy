package digestauth

import (
  "fmt"

	"github.com/mholt/caddy"
  "github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("digestauth", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new DigestAuth middleware instance.
func setup(c *caddy.Controller) error {
  cfg := httpserver.GetConfig(c)
  root := cfg.Root
  fmt.Printf("Root: %s\n", root)

  rules, err := parseDigestAuth(c)
  if err != nil {
    fmt.Println(err)
    return err
  }

  fmt.Println(rules)

	return nil
}

func parseDigestAuth(c *caddy.Controller) ([]Rule, error) {
  var rules []Rule
  // cfg := httpserver.GetConfig(c)

  for c.Next() {
    var rule Rule

    args := c.RemainingArgs()

    if len(args) != 3 {
      return rules, c.ArgErr()
    }

    rule.Resources = append(rule.Resources, args[0])
    rule.Username = args[1]
    // if rule.Password, err = passwordMatcher(rule.Username, args[2], cfg.Root); err != nil {
    //   return rules, c.Errf("Get password matcher from %s: %v", c.Val(), err)
    // }

    rules = append(rules, rule)
  }

  return rules, nil
}
