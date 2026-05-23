package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

func cmdZone(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("zone subcommand required (list, add, remove, reload, export)")
	}

	switch args[0] {
	case "list":
		result, err := apiGet("/api/v1/zones")
		if err != nil {
			return err
		}
		zones, ok := result["zones"].([]interface{})
		if !ok {
			return fmt.Errorf("unexpected response format")
		}
		if len(zones) == 0 {
			fmt.Println("No zones configured")
			return nil
		}
		fmt.Printf("%-40s %s\n", "ZONE", "RECORDS")
		fmt.Printf("%-40s %s\n", strings.Repeat("-", 40), strings.Repeat("-", 10))
		for _, z := range zones {
			if zm, ok := z.(map[string]interface{}); ok {
				name, _ := zm["name"].(string)
				records, _ := zm["records"].(float64)
				fmt.Printf("%-40s %d\n", name, int(records))
			}
		}

	case "add":
		if len(args) < 2 {
			return fmt.Errorf("zone name required: dnsctl zone add <zone> [nameserver]")
		}
		zoneName := args[1]
		// Normalize: drop any trailing dot before composing default
		// nameserver / admin-email FQDNs. Pre-fix, calling
		// `dnsctl zone add example.com.` produced a double-dotted
		// ns/admin name like `ns1.example.com..` and the server's
		// SOA validation rejected it; users who reflexively typed
		// the absolute form got an unhelpful 400 instead of a
		// working zone.
		bareZone := strings.TrimSuffix(zoneName, ".")
		ns := "ns1." + bareZone + "."
		if len(args) > 2 {
			ns = args[2]
		}
		body := map[string]interface{}{
			"name":        zoneName,
			"nameservers": []string{ns},
			"admin_email": "admin." + bareZone + ".",
			"ttl":         3600,
		}
		b, _ := json.Marshal(body)
		result, err := apiPost("/api/v1/zones", string(b))
		if err != nil {
			return err
		}
		if msg, ok := result["message"].(string); ok {
			fmt.Println(msg)
		}

	case "remove":
		if len(args) < 2 {
			return fmt.Errorf("zone name required: dnsctl zone remove <zone>")
		}
		zoneName := args[1]
		result, err := apiDelete("/api/v1/zones/"+url.PathEscape(zoneName), "")
		if err != nil {
			return err
		}
		if msg, ok := result["message"].(string); ok {
			fmt.Println(msg)
		}

	case "reload":
		if len(args) < 2 {
			return fmt.Errorf("zone name required: dnsctl zone reload <zone>")
		}
		zoneName := args[1]
		result, err := apiPost("/api/v1/zones/reload?zone="+url.QueryEscape(zoneName), "")
		if err != nil {
			return err
		}
		if msg, ok := result["message"].(string); ok {
			fmt.Println(msg)
		}

	case "export":
		if len(args) < 2 {
			return fmt.Errorf("zone name required: dnsctl zone export <zone>")
		}
		zoneName := args[1]
		body, err := apiGetRaw("/api/v1/zones/" + url.PathEscape(zoneName) + "/export")
		if err != nil {
			return err
		}
		os.Stdout.Write(body)
		if len(body) > 0 && body[len(body)-1] != '\n' {
			fmt.Println()
		}

	default:
		return fmt.Errorf("unknown zone subcommand: %s (supported: list, add, remove, reload, export)", args[0])
	}
	return nil
}
