import dns.message
import dns.query
import dns.dnssec
import dns.resolver
import dns.name

# List of root servers
ROOT_SERVERS = [
    "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",
    "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
    "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
    "202.12.27.33"
]

def resolve_dns(domain, qtype):
    if qtype != 'A':
        print("This resolver only supports DNSSEC validation for type 'A' queries.")
        return

    for root_server in ROOT_SERVERS:
        try:
            # Step 1: Query the root server with DNSSEC
            query = dns.message.make_query(domain, qtype, want_dnssec=True)
            response = dns.query.udp(query, root_server, timeout=5)

            # Validate the root zone's DNSKEY
            root_keys = dns.resolver.resolve('.', 'DNSKEY')
            validate_dnssec(response, root_keys)

            # Step 2: Extract TLD server from additional section
            tld_server = extract_server_from_additional(response)
            if not tld_server:
                print(f"Failed to find TLD server using root server {root_server}. Trying next root server.")
                continue

            # Step 3: Query the TLD server with DNSSEC
            query = dns.message.make_query(domain, qtype, want_dnssec=True)
            response = dns.query.udp(query, tld_server, timeout=5)

            # Validate TLD zone's DNSKEY
            tld = dns.name.from_text(domain).split(depth=1)[1].to_text()
            tld_keys = get_dnskey(tld, tld_server)
            validate_dnssec(response, tld_keys)

            # Step 4: Extract authoritative server from additional section
            auth_server = extract_server_from_additional(response)
            if not auth_server:
                auth_server = resolve_ns(extract_ns_from_authority(response))

            if not auth_server:
                print(f"Failed to find authoritative server for {domain}. Trying next root server.")
                continue

            # Step 5: Query the authoritative server with DNSSEC
            query = dns.message.make_query(domain, qtype, want_dnssec=True)
            response = dns.query.udp(query, auth_server, timeout=5)

            # Validate domain zone's DNSKEY and A record RRSIG
            domain_keys = get_dnskey(domain, auth_server)
            validate_dnssec(response, domain_keys)

            # Step 6: Handle and print the validated A record response
            handle_a_response(response, domain)
            
            break  # Exit loop after successful resolution and validation

        except dns.dnssec.ValidationFailure as e:
            print(f"DNSSEC validation failed: {e}")
        except Exception as e:
            print(f"Error with server {root_server}: {e}. Trying next root server.")

def validate_dnssec(response, keys):
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.A or rrset.rdtype == dns.rdatatype.DNSKEY:
            rrsig = next((r for r in response.answer if r.rdtype == dns.rdatatype.RRSIG), None)
            if rrsig:
                try:
                    dns.dnssec.validate(rrset, rrsig, keys)
                    print(f"Validated RRSIG for {rrset.name}")
                except dns.dnssec.ValidationFailure as e:
                    raise dns.dnssec.ValidationFailure(f"DNSSEC validation failed for {rrset.name}: {e}")

def get_dnskey(domain, server):
    query = dns.message.make_query(domain, 'DNSKEY', want_dnssec=True)
    response = dns.query.udp(query, server, timeout=5)
    return response.answer

def extract_server_from_additional(response):
    for rrset in response.additional:
        if rrset.rdtype == dns.rdatatype.A:
            return rrset[0].address
    return None

def extract_ns_from_authority(response):
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            return rrset[0].target.to_text()
    return None

def resolve_ns(ns_name):
    query = dns.message.make_query(ns_name, 'A')
    response = dns.query.resolve(query)
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.A:
            return rrset[0].address
    return None

def handle_a_response(response, domain):
    print(f"A records for {domain}:")
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.A:
            for item in rrset.items:
                print(item.address)

if __name__ == "__main__":
    domain = "www.paypal.com"
    qtype = "A"
    
    resolve_dns(domain, qtype)
