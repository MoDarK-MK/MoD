from core.cve_payloads import CVEPayloads

CVEPayloads.initialize()
all_cves = CVEPayloads.get_all_cves()

advanced = [c for c in all_cves if c['id'].startswith('CVE-2024-51')]
extended = [c for c in all_cves if c['id'].startswith('CVE-2024-52')]

print(f"Total CVEs: {len(all_cves)}")
print(f"Advanced CVEs (CVE-2024-51xxx): {len(advanced)}")
print(f"Extended CVEs (CVE-2024-52xxx): {len(extended)}")
print(f"\n=== Extended CVEs Sample ===")
for cve in extended[:10]:
    print(f"{cve['id']}: {cve['name']} (Score: {cve['score']})")
