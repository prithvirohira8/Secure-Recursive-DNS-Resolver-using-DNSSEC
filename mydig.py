import dns.message
import dns.query
import dns.name
import time
import sys
import dns.rdata

# List of root servers
ROOT_SERVERS = [
    "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",
    "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
    "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
    "202.12.27.33"
]

def resolve_dns(domain, qtype):
    # Iterate through root servers until a response is received
    for root_server in ROOT_SERVERS:
        try:
            # Step 1: Query the root server
            query = dns.message.make_query(domain, qtype)
            response = dns.query.udp(query, root_server, timeout=5)
            
            # Step 2: Extract the TLD server from the additional section
            tld_server = None
            for rrset in response.additional:
                if rrset.rdtype == dns.rdatatype.A:
                    tld_server = rrset[0].address
                    break
            
            if not tld_server:
                print(f"Failed to find TLD server using root server {root_server}. Trying next root server.")
                continue
            
            # Step 3: Query the TLD server
            query = dns.message.make_query(domain, qtype)
            response = dns.query.udp(query, tld_server, timeout=5)
            
            # Step 4: Extract the authoritative server from the additional section
            auth_server = None
            for rrset in response.additional:
                if rrset.rdtype == dns.rdatatype.A:
                    auth_server = rrset[0].address
                    break
            
            if not auth_server:
                # If additional section is empty, resolve the NS records
                ns_records = []
                for rrset in response.authority:
                    if rrset.rdtype == dns.rdatatype.NS:
                        ns_records.extend(rrset)
                
                if not ns_records:
                    print(f"Failed to find authoritative server using root server {root_server}. Trying next root server.")
                    continue
                
                # Resolve the first NS record to get its IP address
                ns_domain = ns_records[0].target.to_text()
                print(f"Resolving NS record: {ns_domain}")
                auth_server = resolve_ns(ns_domain)
                if not auth_server:
                    print(f"Failed to resolve NS record using root server {root_server}. Trying next root server.")
                    continue
            
            # Step 5: Query the authoritative server
            query = dns.message.make_query(domain, qtype)
            response = dns.query.udp(query, auth_server, timeout=5)
            
            # Step 6: Handle the response based on the query type
            if qtype == 'A':
                handle_a_response(response, domain)
            elif qtype == 'NS':
                handle_ns_response(response, domain)
            elif qtype == 'MX':
                handle_mx_response(response, domain)
            else:
                print(f"Unsupported query type: {qtype}")
            
            # If we reach here, the resolution was successful, so break the loop
            break
        
        except Exception as e:
            print(f"Error with root server {root_server}: {e}. Trying next root server.")
            continue

def resolve_ns(ns_domain):
    # Iterate through root servers until a response is received
    for root_server in ROOT_SERVERS:
        try:
            # Step 1: Query the root server
            query = dns.message.make_query(ns_domain, 'A')
            response = dns.query.udp(query, root_server, timeout=5)
            
            # Step 2: Extract the TLD server from the additional section
            tld_server = None
            for rrset in response.additional:
                if rrset.rdtype == dns.rdatatype.A:
                    tld_server = rrset[0].address
                    break
            
            if not tld_server:
                print(f"Failed to find TLD server for NS resolution using root server {root_server}. Trying next root server.")
                continue
            
            # Step 3: Query the TLD server
            query = dns.message.make_query(ns_domain, 'A')
            response = dns.query.udp(query, tld_server, timeout=5)
            
            # Step 4: Extract the authoritative server from the additional section
            auth_server = None
            for rrset in response.additional:
                if rrset.rdtype == dns.rdatatype.A:
                    auth_server = rrset[0].address
                    break
            
            if not auth_server:
                print(f"Failed to find authoritative server for NS resolution using root server {root_server}. Trying next root server.")
                continue
            
            # Step 5: Query the authoritative server
            query = dns.message.make_query(ns_domain, 'A')
            response = dns.query.udp(query, auth_server, timeout=5)
            
            # Step 6: Extract the IP address of the NS record
            if len(response.answer) > 0:
                for rrset in response.answer:
                    if rrset.rdtype == dns.rdatatype.A:
                        return rrset[0].address
            
            print(f"Failed to resolve NS record using root server {root_server}. Trying next root server.")
            continue
        
        except Exception as e:
            print(f"Error with root server {root_server}: {e}. Trying next root server.")
            continue
    
    print("Failed to resolve NS record after trying all root servers.")
    return None

def handle_a_response(response, domain):
    # Check for CNAME records
    if len(response.answer) > 0:
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                # If a CNAME is found, resolve it recursively
                cname = rrset[0].target.to_text()
                print(f"CNAME found: {cname}")
                return resolve_dns(cname, 'A')
            elif rrset.rdtype == dns.rdatatype.A:
                # If an A record is found, print the result
                print(f"QUESTION SECTION: {domain} IN A")
                print("ANSWER SECTION:")
                for rr in rrset:
                    print(f"{domain} IN A {rr.address}")
                print(f"Query time: {response.time * 1000:.0f} msec")
                print(f"WHEN: {time.ctime()}")
                print(f"MSG SIZE rcvd: {len(response.to_wire())}")
                return
    print("\nCheck the authority section of the response\n")
    print(response)
    print("No answer found.")

def handle_ns_response(response, domain):
    ns_records = []
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NS or rrset.rdtype == dns.rdatatype.SOA:
            ns_records.extend(rrset)
    
    if ns_records:
        print(f"QUESTION SECTION: {domain} IN NS")
        print("AUTHORITY SECTION:")
        for rr in ns_records:
            print(f"{domain} IN NS {rr}")
        print(f"Query time: {response.time * 1000:.0f} msec")
        print(f"WHEN: {time.ctime()}")
        print(f"MSG SIZE rcvd: {len(response.to_wire())}")
    else:
        print("No NS records found.")

def handle_mx_response(response, domain):
    mx_records = []
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.MX or rrset.rdtype == dns.rdatatype.SOA:
            mx_records.extend(rrset)
    
    if mx_records:
        print(f"QUESTION SECTION: {domain} IN MX")
        print("ANSWER SECTION:")
        for rr in mx_records:
            print(f"{domain} IN MX {rr}")
        print(f"Query time: {response.time * 1000:.0f} msec")
        print(f"WHEN: {time.ctime()}")
        print(f"MSG SIZE rcvd: {len(response.to_wire())}")
    else:
        print("No MX records found.")

def main():
    if len(sys.argv) != 3:
        print("Usage: python mydig.py <domain> <query_type>")
        sys.exit(1)

    domain = sys.argv[1]
    qtype = sys.argv[2]
    resolve_dns(domain, qtype)

if __name__ == "__main__":
    main()