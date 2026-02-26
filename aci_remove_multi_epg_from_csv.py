import cobra.mit.access
import cobra.mit.request
import cobra.mit.session
import cobra.model.fv
import urllib3
from cobra.internal.codec.xmlcodec import toXMLStr
import getpass
import csv
import os

# --- SETTINGS ---
INPUT_FILE = 'aci_port_epg_report.csv'
DRY_RUN = True  # SET TO False TO ACTUALLY DELETE
POD_ID = '1'

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def remove_epg_paths_multi():
    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found.")
        return

    host = input('APIC IP/Hostname: ')
    user = input('Username: ')
    password = getpass.getpass('Password: ')
    
    lsession = cobra.mit.session.LoginSession(f'https://{host}', user, password)
    mo_dir = cobra.mit.access.MoDirectory(lsession)
    try:
        mo_dir.login()
    except Exception as e:
        print(f"Login failed: {e}")
        return

    config_request = cobra.mit.request.ConfigRequest()
    match_count = 0

    with open(INPUT_FILE, mode='r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            node = row['Node']
            interface = row['Interface']
            status = row['Status']
            epg_string = row['Deployed_EPGs']

            # Only process if port is NOT 'up' and has EPGs assigned
            if status != 'up' and epg_string != 'None (Unbound)':
                
                # Split EPGs by "|"
                epg_list = [e.strip() for e in epg_string.split('|')]
                
                print(f"\nProcessing Interface {node}/{interface} (Status: {status})")
                
                for full_epg_path in epg_list:
                    try:
                        # 1. Split the path FIRST
                        parts = full_epg_path.split('/')
                        if len(parts) != 3:
                            print(f" [SKIP] Malformed EPG path: {full_epg_path}")
                            continue
                        
                        tenant, app_prof, epg_name = parts

                        # 2. Build the DNs SECOND
                        epg_dn = f"uni/tn-{tenant}/ap-{app_prof}/epg-{epg_name}"
                        path_tdn = f"topology/pod-{POD_ID}/paths-{node}/pathep-[{interface}]"
                        binding_dn = f"{epg_dn}/rspathAtt-[{path_tdn}]"

                        # 3. Look up the binding THIRD
                        binding_mo = mo_dir.lookupByDn(binding_dn)
                        
                        if binding_mo:
                            match_count += 1
                            # Mark for deletion
                            binding_mo.delete()
                            
                            # Show the XML that would be sent
                            print(f" [DN PATH] {binding_mo.dn}")
                            print(f" [XML PREVIEW] {toXMLStr(binding_mo)}")
                            
                            if not DRY_RUN:
                                config_request.addMo(binding_mo)
                                print(f" [QUEUED] {full_epg_path}")
                            else:
                                print(f" [DRY RUN] Identified for deletion: {full_epg_path}")
                        else:
                            print(f" [NOT FOUND] Binding already gone for: {full_epg_path}")

                    except Exception as e:
                        print(f" [ERROR] Unexpected error processing {full_epg_path}: {e}")

    # Final Commit Section
    if match_count > 0:
        if not DRY_RUN:
            try:
                print(f"\nCommitting {match_count} changes to APIC...")
                mo_dir.commit(config_request)
                print(f"SUCCESS: Changes applied.")
            except Exception as e:
                print(f"ERROR: Commit failed: {e}")
        else:
            print(f"\nDRY RUN COMPLETE: Found {match_count} changes identified above. Set DRY_RUN=False to execute.")
    else:
        print("\nNo matching associations found to process.")

    mo_dir.logout()

if __name__ == "__main__":
    remove_epg_paths_multi()
