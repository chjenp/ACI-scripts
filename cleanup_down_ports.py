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
    processed_selectors = set()

    try:
        for item in records:
            node = item["node"]
            port = item["port"]
            int_prof = item["int_prof"]
            selector = item["selector"]

            # Double-check the physical port's operational state live on the fabric
            # DN format: topology/pod-1/node-101/sys/phys-[eth1/10]/phys
            port_phys_dn = f"topology/pod-1/node-{node}/sys/phys-[{port}]/phys"
            phys_mo = mo_directory.lookupByDn(port_phys_dn)

            if not phys_mo:
                print(f"[NOT FOUND] Physical Port {node} {port} does not exist in fabric.")
                continue

            oper_st = phys_mo.operSt

            if oper_st == "up":
                ports_up_skipped += 1
                print(f"[SAFETY SKIP] Port {node} {port} was 'down' in CSV, but is now 'UP' in APIC. Skipping.")
                continue

            ports_verified_down += 1
            print(f"[DOWN] Port {node} {port} is verified DOWN. Locating configuration...")

            # Build the DN for the Interface Selector
            selector_dn = f"uni/infra/accportprof-{int_prof}/hports-{selector}-typ-range"
            
            # Prevent attempting to delete the exact same selector multiple times 
            # (e.g. if eth1/1 and eth1/2 use the exact same selector name)
            if selector_dn in processed_selectors:
                print(f"  -> [DUPLICATE] Selector {selector_dn} is already queued for deletion.")
                continue

            selector_mo = mo_directory.lookupByDn(selector_dn)

            if not selector_mo:
                print(f"  -> [NOT FOUND] Profile Selector {selector_dn} is already deleted.")
                continue

            # Add to set so we don't duplicate it
            processed_selectors.add(selector_dn)
            selector_mo.delete()
            print(f"  -> [MATCH] Deleting Selector: {selector_dn}")

            if not DRY_RUN:
                config_request.addMo(selector_mo)
                queued += 1
                print("  -> [QUEUED] Marked for deletion")
            else:
                print("  -> [DRY-RUN] No commit will be performed")

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
