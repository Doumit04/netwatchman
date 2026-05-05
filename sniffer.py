from scapy.all import rdpcap #read pcap
import os


def read_pcap(filepath):
    """
    Reads a PCAP file and returns a list of raw Scapy packets.
    """    

    if not os.path.exists(filepath):
        print(f"[ERROR]File not found: {filepath}")
        return []
    
    print(f"[*] Reading PCAP file: {filepath}")
    packets = rdpcap(filepath) #open this file and read all packets inside it
    print(f"[*] Total packets loaded: {len(packets)}")
    return packets