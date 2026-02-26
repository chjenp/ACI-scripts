import cobra.mit.access
import cobra.mit.request
import cobra.mit.session
import cobra.model.infra
import cobra.model.ethpm
import urllib3
import getpass
import csv
import re

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_aci_port_mapping_and_status():
    # --- Connection Details ---
    host = input('APIC IP/Hostname: ')
    URL = f'https://{host}'
    USER = input('Username: ')
    PASS = getpass.getpass('Password: ')
    OUTPUT_FILE = 'aci_port_status_report.csv'

    lsession = cobra.mit.session.LoginSession(URL, USER, PASS)
    mo_dir = cobra.mit.access.MoDirectory(lsession)

    try:
        mo_dir.login()
    except Exception as e:
        print(f"Login failed: {e}")
        return

    print("Step 1: Gathering Operational Status (ethpmPhysIf)...")
    # Map of "node/port" -> "status" (e.g., "101/1/48" -> "up")
    oper_status_map = {}
    status_query = cobra.mit.request.ClassQuery("ethpmPhysIf")
    all_statuses = mo_dir.query(status_query)
    
    for stat in all_statuses:
        # DN looks like: topology/pod-1/node-101/sys/phys-[eth1/48]/phys
        dn_str = str(stat.dn)
        try:
            node_id = re.search(r'node-(\d+)', dn_str).group(1)
            port_id = re.search(r'phys-\[eth(.*?/.*?)\]', dn_str).group(1)
            key = f"{node_id}/{port_id}"
            oper_status_map[key] = stat.operSt
        except (AttributeError, IndexError):
            continue

    print("Step 2: Mapping Profiles to Nodes and Ports...")
    # Map Interface Profile Name -> List of (Selector, Port Ranges, Policy Group)
    prof_map = {}
    intf_query = cobra.mit.request.ClassQuery("infraAccPortP")
    intf_query.subtree = 'full'
    interface_profiles = mo_dir.query(intf_query)

    for prof in interface_profiles:
        selectors = []
        for child in prof.children:
            if isinstance(child, cobra.model.infra.HPortS):
                port_blocks = []
                pg = "None"
                for gc in child.children:
                    if isinstance(gc, cobra.model.infra.PortBlk):
                        port_blocks.append((int(gc.fromPort), int(gc.toPort)))
                    if isinstance(gc, cobra.model.infra.RsAccBaseGrp):
                        pg = str(gc.tDn).split('/')[-1]
                selectors.append({'name': child.name, 'blocks': port_blocks, 'pg': pg})
        prof_map[prof.name] = selectors

    print("Step 3: Correlating Data...")
    report_data = []
    node_query = cobra.mit.request.ClassQuery("infraNodeP")
    node_query.subtree = 'full'
    switch_profiles = mo_dir.query(node_query)

    for sp in switch_profiles:
        # Identify associated Node IDs
        nodes = []
        for child in sp.children:
            if isinstance(child, cobra.model.infra.LeafS):
                for gs in child.children:
                    if isinstance(gs, cobra.model.infra.NodeBlk):
                        # Add every node ID in the range
                        for n_id in range(int(gs.from_), int(gs.to_) + 1):
                            nodes.append(str(n_id))
        
        # Identify linked Interface Profiles
        for child in sp.children:
            if isinstance(child, cobra.model.infra.RsAccPortP):
                prof_name = str(child.tDn).split('accportprof-')[-1]
                selectors = prof_map.get(prof_name, [])

                for node in nodes:
                    for s in selectors:
                        for block in s['blocks']:
                            # Expand port blocks (e.g., 1-2 becomes 1/1 and 1/2)
                            for p_num in range(block[0], block[1] + 1):
                                port_full_id = f"1/{p_num}" # Note: ACI Access Ports are typically on card 1
                                status_key = f"{node}/{port_full_id}"
                                actual_status = oper_status_map.get(status_key, "N/A (Not Found/SFP Missing)")

                                report_data.append({
                                    'Node': node,
                                    'Switch_Profile': sp.name,
                                    'Interface_Profile': prof_name,
                                    'Selector': s['name'],
                                    'Interface': f"eth{port_full_id}",
                                    'Port_Status': actual_status,
                                    'Policy_Group': s['pg']
                                })

    # Write to CSV
    with open(OUTPUT_FILE, mode='w', newline='') as csvfile:
        fieldnames = ['Node', 'Switch_Profile', 'Interface_Profile', 'Selector', 'Interface', 'Port_Status', 'Policy_Group']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report_data)

    print(f"Success! Mapping with live status exported to {OUTPUT_FILE}")
    mo_dir.logout()

if __name__ == "__main__":
    get_aci_port_mapping_and_status()
