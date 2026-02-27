import cobra.mit.access
import cobra.mit.request
import cobra.mit.session
import cobra.model.infra
import cobra.model.fv
import urllib3
import getpass
import csv
import re

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_aci_comprehensive_report():
    # --- Connection Details ---
    host = input('APIC IP/Hostname: ')
    URL = f'https://{host}'
    USER = input('Username: ')
    PASS = getpass.getpass('Password: ')
    OUTPUT_FILE = 'aci_port_epg_report.csv'

    lsession = cobra.mit.session.LoginSession(URL, USER, PASS)
    mo_dir = cobra.mit.access.MoDirectory(lsession)

    try:
        mo_dir.login()
    except Exception as e:
        print(f"Login failed: {e}")
        return

    print("Step 1: Gathering Operational Status (ethpmPhysIf)...")
    oper_status_map = {}
    status_query = cobra.mit.request.ClassQuery("ethpmPhysIf")
    all_statuses = mo_dir.query(status_query)
    for stat in all_statuses:
        dn_str = str(stat.dn)
        try:
            node_id = re.search(r'node-(\d+)', dn_str).group(1)
            port_id = re.search(r'phys-\[eth(.*?/.*?)\]', dn_str).group(1)
            oper_status_map[f"{node_id}/{port_id}"] = stat.operSt
        except (AttributeError, IndexError):
            continue

    print("Step 2: Gathering Static EPG Bindings (fvRsPathAtt)...")
    # Map "node/port" -> List of EPGs ("Tenant/AppProf/EPG")
    epg_binding_map = {}
    epg_query = cobra.mit.request.ClassQuery("fvRsPathAtt")
    all_bindings = mo_dir.query(epg_query)
    
    for binding in all_bindings:
        # DN: uni/tn-T1/ap-A1/epg-E1/rspathAtt-[topology/pod-1/paths-101/pathep-[eth1/1]]
        dn_str = str(binding.dn)
        t_dn_str = str(binding.tDn) # topology/pod-1/paths-101/pathep-[eth1/1]
        
        try:
            # Extract EPG Info
            tenant = re.search(r'tn-(.*?)/', dn_str).group(1)
            app_prof = re.search(r'ap-(.*?)/', dn_str).group(1)
            epg = re.search(r'epg-(.*?)/', dn_str).group(1)
            epg_full_name = f"{tenant}/{app_prof}/{epg}"
            
            # Extract Node/Port from target DN
            node_id = re.search(r'paths-(\d+)', t_dn_str).group(1)
            port_id = re.search(r'pathep-\[eth(.*?/.*?)\]', t_dn_str).group(1)
            key = f"{node_id}/{port_id}"
            
            if key not in epg_binding_map:
                epg_binding_map[key] = []
            if epg_full_name not in epg_binding_map[key]:
                epg_binding_map[key].append(epg_full_name)
        except (AttributeError, IndexError):
            continue

    print("Step 3: Gathering Logical Profiles (infraAccPortP)...")
    prof_map = {}
    intf_query = cobra.mit.request.ClassQuery("infraAccPortP")
    intf_query.subtree = 'full'
    for prof in mo_dir.query(intf_query):
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

    print("Step 4: Correlating and Exporting...")
    report_data = []
    node_query = cobra.mit.request.ClassQuery("infraNodeP")
    node_query.subtree = 'full'
    for sp in mo_dir.query(node_query):
        nodes = []
        for child in sp.children:
            if isinstance(child, cobra.model.infra.LeafS):
                for gs in child.children:
                    if isinstance(gs, cobra.model.infra.NodeBlk):
                        for n_id in range(int(gs.from_), int(gs.to_) + 1):
                            nodes.append(str(n_id))
        
        for child in sp.children:
            if isinstance(child, cobra.model.infra.RsAccPortP):
                prof_name = str(child.tDn).split('accportprof-')[-1]
                for node in nodes:
                    for s in prof_map.get(prof_name, []):
                        for block in s['blocks']:
                            for p_num in range(block[0], block[1] + 1):
                                port_key = f"{node}/1/{p_num}"
                                status = oper_status_map.get(port_key, "N/A")
                                epgs = epg_binding_map.get(port_key, ["None (Unbound)"])

                                report_data.append({
                                    'Node': node,
                                    'Interface': f"eth1/{p_num}",
                                    'Status': status,
                                    'Deployed_EPGs': " | ".join(epgs),
                                    'Interface_Profile': prof_name,
                                    'Selector': s['name'],
                                    'Policy_Group': s['pg'],
                                    'Switch_Profile': sp.name
                                })

    with open(OUTPUT_FILE, mode='w', newline='') as csvfile:
        fieldnames = ['Node', 'Interface', 'Status', 'Deployed_EPGs', 'Interface_Profile', 'Selector', 'Policy_Group', 'Switch_Profile']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report_data)

    print(f"Success! Comprehensive report exported to {OUTPUT_FILE}")
    mo_dir.logout()

if __name__ == "__main__":
    get_aci_comprehensive_report()
