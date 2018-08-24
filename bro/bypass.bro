#TODO: use the library directly, not system
function shunt(c: connection) {
    local id = c$id;
    local tool = fmt("%s/../xdp_bypass_cli", @DIR);
    local cmd = "";
    local proto = get_port_transport_proto(id$resp_p);

    skip_further_processing(c$id);
    cmd = fmt("%s %s %s %s %s %s &", tool, proto,
        id$orig_h, port_to_count(id$orig_p),
        id$resp_h, port_to_count(id$resp_p)
    );
    system(cmd);

    cmd = fmt("%s %s %s %s %s %s &", tool, proto,
        id$resp_h, port_to_count(id$resp_p),
        id$orig_h, port_to_count(id$orig_p)
    );
    system(cmd);
}

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
{
    if (/nflxvideo|google|youtube/ !in cert$subject)
        return;
    print cert$subject;
    for (c in f$conns) {
        shunt(f$conns[c]);
    }
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    if (name == "USER-AGENT" && /Netflix/ in value) {
        print "Netflix", c$id, value;
        shunt(c);
    }
}
