import sys
import getpass
import urllib3
import cobra.mit.access
import cobra.mit.request
import cobra.mit.session
from cobra.internal.codec.xmlcodec import toXMLStr

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- SETTINGS ---
DRY_RUN = True  # SET TO False TO ACTUALLY DELETE
TENANT = "Production-TNT"
DOMAIN_DN = "uni/vmmp-VMware/dom-W7_MX1000_VDS-New"


def parse_input_file(file_path):
    records = []
    seen = set()
    malformed = 0

    with open(file_path, encoding="utf-8") as file_handle:
        for line_number, raw_line in enumerate(file_handle, start=1):
            line = raw_line.strip()
            if not line:
                continue

            # Skip the header row specifically matching your file
            if line_number == 1 and "application profile" in line.lower():
                continue

            if "," in line:
                parts = [part.strip() for part in line.split(",")]
            else:
                parts = line.split()

            if len(parts) < 2:
                malformed += 1
                print(f"[SKIP] Line {line_number}: malformed entry -> {line}")
                continue

            # Column 1 is AP, Column 2 is EPG
            ap_name = parts[0]
            epg_name = parts[1]

            key = (ap_name, epg_name)
            if key in seen:
                continue

            seen.add(key)
            records.append(key)

    return records, malformed


def main():
    # 1. Get input file from command line argument
    if len(sys.argv) < 2:
        print("Usage: python remove_old_VMM.py <input_file>")
        sys.exit(1)
        
    input_file = sys.argv[1]

    # 2. Interactively ask for credentials and APIC details
    print("=== APIC Authentication ===")
    apic = input("APIC IP or hostname: ").strip()
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    if not apic or not username or not password:
        print("Error: APIC IP, username, and password are all required. Exiting.")
        sys.exit(1)

    # 3. Parse the file
    records, malformed = parse_input_file(input_file)
    if not records:
        print("No valid AP/EPG entries found in input file. Exiting.")
        return

    print(f"\nParsed {len(records)} unique AP/EPG entries ({malformed} malformed lines skipped).")
    print(f"Mode: {'DRY-RUN' if DRY_RUN else 'EXECUTE'}")

    # 4. Login to APIC
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
    found = 0
    queued = 0
    missing = 0

    try:
        for ap_name, epg_name in records:
            relation_dn = (
                f"uni/tn-{TENANT}/ap-{ap_name}/epg-{epg_name}"
                f"/rsdomAtt-[{DOMAIN_DN}]"
            )
            relation_mo = mo_directory.lookupByDn(relation_dn)

            if not relation_mo:
                missing += 1
                print(f"[NOT FOUND] {relation_dn}")
                continue

            found += 1
            relation_mo.delete()
            print(f"[MATCH] {relation_dn}")
            print(f"[XML] {toXMLStr(relation_mo)}")

            if not DRY_RUN:
                config_request.addMo(relation_mo)
                queued += 1
                print("[QUEUED] Marked for deletion")
            else:
                print("[DRY-RUN] No commit will be performed")

        if not DRY_RUN and queued > 0:
            print(f"\nCommitting {queued} deletion(s) to APIC...")
            mo_directory.commit(config_request)
            print("SUCCESS: Changes committed.")
        elif not DRY_RUN and queued == 0:
            print("\nNo matching domain attachments found. Nothing committed.")
        else:
            print("\nDry-run complete. Set DRY_RUN=False to apply changes.")

        print(
            f"\nSummary: parsed={len(records)}, found={found}, missing={missing}, queued={queued}, malformed={malformed}"
        )
    except Exception as error:
        print(f"Execution failed: {error}")
    finally:
        mo_directory.logout()

if __name__ == "__main__":
    main()
