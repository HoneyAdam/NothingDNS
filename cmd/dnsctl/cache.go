package main

import (
	"fmt"
	"net/url"
)

func cmdCache(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("cache subcommand required (flush, stats)")
	}

	switch args[0] {
	case "stats":
		result, err := apiGet("/api/v1/cache/stats")
		if err != nil {
			return err
		}
		fmt.Println("Cache Statistics:")
		fmt.Printf("  Size:      %v\n", result["size"])
		fmt.Printf("  Capacity:  %v\n", result["capacity"])
		fmt.Printf("  Hits:      %v\n", result["hits"])
		fmt.Printf("  Misses:    %v\n", result["misses"])
		if ratio, ok := result["hit_ratio"].(float64); ok {
			fmt.Printf("  Hit Ratio: %.2f%%\n", ratio*100)
		}

	case "flush":
		path := "/api/v1/cache/flush"
		if len(args) > 1 {
			// URL-encode the name so a record name containing query-string
			// delimiters (?, &, =, #) or any other unsafe character doesn't
			// fall outside its key=value slot and corrupt the request. The
			// previous code just concatenated the raw arg, so a name like
			// "evil.example?force=true" would smuggle an extra parameter
			// past the API's flush handler.
			path = "/api/v1/cache/flush?name=" + url.QueryEscape(args[1])
		}
		result, err := apiPost(path, "")
		if err != nil {
			return err
		}
		if msg, ok := result["message"].(string); ok {
			fmt.Println(msg)
		}

	default:
		return fmt.Errorf("unknown cache subcommand: %s", args[0])
	}
	return nil
}
