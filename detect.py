from scapy.all import rdpcap
from collections import defaultdict
import numpy as np

def analyze_beacons(pcap_file):
    packets = rdpcap(pcap_file)
    
    # Organize packets by destination IP and port
    flows = defaultdict(list)
    for pkt in packets:
        if 'IP' in pkt:
            dst_ip = pkt['IP'].dst
            if 'TCP' in pkt or 'UDP' in pkt:
                dst_port = pkt['TCP'].dport if 'TCP' in pkt else pkt['UDP'].dport
                flows[(dst_ip, dst_port)].append(pkt.time)
    
    # Analyze timing for each flow to find potential beacons
    for flow, times in flows.items():
        if len(times) > 1:  # Ensure there are at least two packets to analyze timing
            intervals = np.diff(times)
            mean = np.mean(intervals)
            std_dev = np.std(intervals)
            if std_dev / mean < 0.1 and mean < 60:  # Threshold criteria for beaconing
                print(f"Potential beacon detected: {flow} with interval ~{mean:.2f}s (std dev: {std_dev:.2f})")

# Example usage
pcap_file = 'path_to_your_pcap_file.pcap'
analyze_beacons(pcap_file)
