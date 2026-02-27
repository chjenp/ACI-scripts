import sys
import csv
import getpass
import urllib3
import cobra.mit.access
import cobra.mit.request
import cobra.mit.session
from cobra.internal.codec.xmlcodec import toXMLStr

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- SETTINGS ---
DRY_RUN = True  # SET TO False TO ACTUALLY DELETE

def parse_inventory_file(file_path):
    records = []
    
    with open(file_path, encoding="utf-8") as file_handle:
        # Using csv.DictReader with tab delimiter to perfectly match your file
        reader = csv.DictReader(file_handle, delimiter=',')
        
        for line_number, row in enumerate(reader, start=2):
            # Fallback if the file got converted to spaces instead of tabs during copy/paste
            if len(row) < 5:
                print(f"[WARNING] Line {line_number} doesn't look comma seprated. Ensure your file uses Tabs.")
                continue

            node = row.get('Node', '').strip()
            interface = row.get('Interface', '').strip()
            status = row.get('Status', '').strip().lower()
            int_prof = row.get('Interface_Profile', '').strip()
            selector = row.get('Selector', '').strip()

            # We only care about ports marked as "down" in the CSV
            if status == 'down':
                if not int_prof or not selector or int_prof.lower() == 'none':
                    print(f"[SKIP] Node {node} {interface} is down but has no profile configured.")
                    continue
                    
                records.append({
                    "node": node,
                    "port": interface,
                    "int_prof": int_prof,
                    "selector": selector
                })

    return records

def main():
    if len(sys.argv) < 2:
        print("Usage: python cleanup_down_ports.py <inventory_file.csv/txt>")
        sys.exit(1)
        
    input_file = sys.argv[1]

    print("=== APIC Authentication ===")
    apic = input("APIC IP or hostname: ").strip()
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    if not apic or not username or not password:
        print("Error: APIC IP, username, and password are all required. Exiting.")
        sys.exit(1)

    # 1. Parse the TSV file for DOWN ports
    print("\nReading inventory file...")
    records = parse_inventory_file(input_file)
    if not records:
        print("No valid 'down' ports with profiles found in input file. Exiting.")
        return

    print(f"Found {len(records)} 'down' ports to process.")
    print(f"Mode: {'DRY-RUN' if DRY_RUN else 'EXECUTE'}")

    # 2. Login to APIC
    login_session = cobra.mit.session.LoginSession(
        f"https://{apic}",
        username,
        password,
        secure=False,
    )
    mo_directory = cobra.mit.access.MoDirectory(login_session)

    try:
        mo_directory.login()
        print("Successfully logged into APIC.\n")
    except Exception as error:
        print(f"Login failed: {error}")
        return

    config_request = cobra.mit.request.ConfigRequest()
    ports_verified_down = 0
    ports_up_skipped = 0
    queued = 0

    try:
        # Group ports by their selector DN
        selectors_to_check = {}
        
        for item in records:
            node = item["node"]
            port = item["port"]
            int_prof = item["int_prof"]
            selector = item["selector"]
            
            selector_dn = f"uni/infra/accportprof-{int_prof}/hports-{selector}-typ-range"
            
            if selector_dn not in selectors_to_check:
                selectors_to_check[selector_dn] = []
                
            selectors_to_check[selector_dn].append({"node": node, "port": port})

        # Now evaluate safety PER SELECTOR
        for selector_dn, ports in selectors_to_check.items():
            print(f"\nEvaluating Selector: {selector_dn}")
            
            safe_to_delete = True
            
            # Check every port inside this selector
            for p in ports:
                port_phys_dn = f"topology/pod-1/node-{p['node']}/sys/phys-[{p['port']}]/phys"
                phys_mo = mo_directory.lookupByDn(port_phys_dn)
                
                if not phys_mo:
                    print(f"  -> [NOT FOUND] Port {p['node']} {p['port']} missing in APIC.")
                    continue
                    
                if phys_mo.operSt == "up":
                    print(f"  -> [DANGER] Port {p['node']} {p['port']} is UP! Aborting deletion for this selector.")
                    safe_to_delete = False
                    ports_up_skipped += 1
                    break # We found an UP port, no need to check the rest in this selector
                else:
                    print(f"  -> [DOWN] Port {p['node']} {p['port']} is verified DOWN.")
                    ports_verified_down += 1
                    
            # Only queue the selector for deletion if NO ports were UP
            if safe_to_delete:
                selector_mo = mo_directory.lookupByDn(selector_dn)
                if not selector_mo:
                    print(f"  -> [ALREADY DELETED] Selector not found in APIC.")
                    continue
                    
                print(f"  -> [SAFE] All evaluated ports are DOWN. Queuing selector for deletion.")
                selector_mo.delete()
                queued += 1
                if not DRY_RUN:
                    config_request.addMo(selector_mo)
                else:
                    print("  -> [DRY-RUN] No commit will be performed.")
            else:
                print(f"  -> [SKIPPED] Selector {selector_dn} kept because at least one port is UP.")

        # 3. Commit changes to APIC
        if not DRY_RUN and queued > 0:
            print(f"\nCommitting {queued} deletion(s) to APIC...")
            mo_directory.commit(config_request)
            print("SUCCESS: Changes committed.")
        elif not DRY_RUN and queued == 0:
            print("\nNo matching configurations found to delete. Nothing committed.")
        else:
            print("\nDry-run complete. Set DRY_RUN=False to apply changes.")

        print(
            f"\nSummary: Total Parsed={len(records)}, Verified DOWN={ports_verified_down}, "
            f"Skipped (Now UP)={ports_up_skipped}, Unique Profiles Queued for Deletion={queued}"
        )

    except Exception as error:
        print(f"Execution failed: {error}")
    finally:
        mo_directory.logout()

if __name__ == "__main__":
    main()