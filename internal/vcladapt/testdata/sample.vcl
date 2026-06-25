// Synthetic VCL for cadish adapt tests — NOT a real production config.
vcl 4.1;
import std;

backend web {
    .host = "10.0.0.1";
    .port = "8080";
    .probe = { .url = "/"; .expected_response = 200; .interval = 5s; .window = 6; .threshold = 3; }
}
backend images {
    .host = "10.0.0.2";
    .port = "9000";
}

acl purgers { "127.0.0.1"; }

sub vcl_recv {
    unset req.http.Accept-Encoding;
    if (req.method == "POST") { return(pass); }
    if (req.url ~ "/admin/" || req.url ~ "/checkout/") { return(pass); }
    if (req.url ~ "\.(jpg|png|css)$") { return(pass); }
    if (req.http.X-Requested-With) { return(pass); }
    if (req.url == "/health") { return(synth(200, "OK")); }
    if (req.http.host ~ "static") { set req.backend_hint = images; }
    set req.http.X-Brand = "acme";
}

sub vcl_hash {
    hash_data(req.url);
    hash_data(req.http.host);
    hash_data(server.ip);
}

sub vcl_backend_response {
    if (beresp.status == 404 || beresp.status == 410) { set beresp.ttl = 60s; set beresp.grace = 1h; }
    if (beresp.status != 200) { set beresp.ttl = 5s; set beresp.uncacheable = true; }
    unset beresp.http.Set-Cookie;
    unset beresp.http.Server;
    set beresp.ttl = 2s;
    set beresp.grace = 24h;
}

sub vcl_deliver {
    set resp.http.X-Cache = "HIT";
    unset resp.http.X-Varnish;
}
