@load frameworks/communication/listen
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl

# Log all connections
redef Log::default_scope_separator = "_";

# Enable packet capture
redef ignore_checksums = T;

