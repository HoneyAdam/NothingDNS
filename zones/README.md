# NothingDNS zone files directory

Place BIND-format zone files here (.zone or .txt).

These are mounted into the Docker container at /etc/nothingdns/zones
and can be referenced from config.yaml under the zones: section.

Example zone file content:

; example.com.zone
$ORIGIN example.com.
$TTL 3600
@       SOA     ns1.example.com. admin.example.com. (
                2024010101 ; Serial
                3600       ; Refresh
                900        ; Retry  
                86400      ; Expire
                300 )      ; Minimum TTL
@       NS      ns1.example.com.
@       NS      ns2.example.com.
@       A       192.0.2.1
ns1     A       192.0.2.1
ns2     A       192.0.2.2
www     A       192.0.2.10

