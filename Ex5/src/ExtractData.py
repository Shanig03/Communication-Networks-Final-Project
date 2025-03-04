import os
import matplotlib.pyplot as plt
from scapy.all import IP, TCP, UDP, ICMP
from collections import Counter
import subprocess
from scapy.all import rdpcap, Raw
import pandas as pd


# Define consistent color palette for the plots (used throughout the script)
CAPTURE_COLORS = [
    "royalblue",
    "seagreen",
    "darkorange",
    "crimson",
    "purple"
]

# Define colors for TCP and UDP protocol visualizations
PROTOCOL_COLORS = {
    "TCP": "cornflowerblue",
    "UDP": "mediumseagreen"
}


# Function to calculate average packet size in the pcap file
def get_average_packet_size(pcap_file):
    packets = rdpcap(pcap_file)  # Read the pcap file
    total_size = sum(len(pkt) for pkt in packets)  # Calculate total packet size
    return total_size / len(packets) if len(packets) > 0 else 0  # Return average packet size


# Function to calculate average TTL (Time to Live) from the pcap file
def get_average_ttl(pcap_file):
    packets = rdpcap(pcap_file)
    ttl_values = [pkt[IP].ttl for pkt in packets if IP in pkt]  # Get TTL values for IP packets
    return sum(ttl_values) / len(ttl_values) if ttl_values else 0  # Return average TTL


# Function to get the distribution of TCP and UDP packets in the pcap file
def get_protocol_distribution(pcap_file):
    packets = rdpcap(pcap_file)
    protocol_counts = {"TCP": 0, "UDP": 0}  # Initialize counters for TCP and UDP

    for pkt in packets:
        if IP in pkt:
            if TCP in pkt:
                protocol_counts["TCP"] += 1  # Count TCP packets
            elif UDP in pkt:
                protocol_counts["UDP"] += 1  # Count UDP packets

    # Calculate percentages for each protocol
    total_ip_packets = sum(protocol_counts.values())
    if total_ip_packets > 0:
        for proto in protocol_counts:
            protocol_counts[proto] = (protocol_counts[proto] / total_ip_packets) * 100

    return protocol_counts


# Function to get the most frequent ports in the pcap file (top 4)
def get_most_frequent_ports(pcap_file):
    packets = rdpcap(pcap_file)
    port_counter = Counter()  # Counter to count the frequency of each port

    for pkt in packets:
        if IP in pkt:
            if TCP in pkt:
                port_counter[pkt[TCP].sport] += 1  # Count source port
                port_counter[pkt[TCP].dport] += 1  # Count destination port
            elif UDP in pkt:
                port_counter[pkt[UDP].sport] += 1  # Count source port
                port_counter[pkt[UDP].dport] += 1  # Count destination port

    most_common_ports = [port for port, _ in port_counter.most_common(4)]  # Get the top 4 frequent ports
    return most_common_ports


# Function to get the percentage usage of specific ports in the pcap file
def get_port_usage_percentage(pcap_file, ports):
    packets = rdpcap(pcap_file)
    total_packets = len(packets)  # Total number of packets
    port_usage = {port: 0 for port in ports}  # Initialize usage counts for each port

    for pkt in packets:
        if IP in pkt:
            if TCP in pkt:
                if pkt[TCP].sport in ports:
                    port_usage[pkt[TCP].sport] += 1  # Count source port usage
                if pkt[TCP].dport in ports:
                    port_usage[pkt[TCP].dport] += 1  # Count destination port usage
            elif UDP in pkt:
                if pkt[UDP].sport in ports:
                    port_usage[pkt[UDP].sport] += 1  # Count source port usage
                if pkt[UDP].dport in ports:
                    port_usage[pkt[UDP].dport] += 1  # Count destination port usage

    # Calculate the usage percentages
    usage_percentages = [(count / total_packets) * 100 for count in port_usage.values()]
    return usage_percentages


# Function to get average TCP window size from the pcap file
def get_average_tcp_window_size(pcap_file):
    packets = rdpcap(pcap_file)
    window_sizes = [pkt[TCP].window for pkt in packets if TCP in pkt]  # Extract window size for TCP packets

    return sum(window_sizes) / len(window_sizes) if window_sizes else 0  # Return average TCP window size


# Process all capture files and return the computed metrics
def process_all_captures(pcap_files):
    avg_packet_sizes = []
    avg_ttls = []
    protocol_distributions = []
    frequent_ports = []
    usage_percentages = []
    capture_names = []
    avg_tcp_window_sizes = []

    for pcap_file in pcap_files:
        capture_names.append(os.path.basename(pcap_file))  # Extract file name from the full path
        avg_packet_sizes.append(get_average_packet_size(pcap_file))  # Average packet size for each capture
        avg_ttls.append(get_average_ttl(pcap_file))  # Average TTL for each capture
        protocol_distributions.append(get_protocol_distribution(pcap_file))  # Protocol distribution (TCP/UDP)

        ports = get_most_frequent_ports(pcap_file)  # Get top frequent ports
        frequent_ports.append(ports)
        usage_percentage = get_port_usage_percentage(pcap_file, ports)  # Get port usage percentage
        usage_percentages.append(usage_percentage)

        # Add the average TCP window size for each capture
        avg_tcp_window_sizes.append(get_average_tcp_window_size(pcap_file))

    return capture_names, avg_packet_sizes, avg_ttls, protocol_distributions, frequent_ports, usage_percentages, avg_tcp_window_sizes


# Function to plot average packet size for all captures
def plot_avg_packet_size(capture_names, avg_packet_sizes):
    os.makedirs(os.path.join("..", "res"), exist_ok=True)  # Create directory if it doesn't exist

    plt.figure(figsize=(12, 4))  # Set the figure size
    plt.bar(capture_names, avg_packet_sizes, color=CAPTURE_COLORS)  # Bar chart for packet sizes
    plt.ylabel("Average Packet Size (Bytes)")  # Y-axis label
    plt.title("Average Packet Size Comparison")  # Title of the plot
    plt.xticks(rotation=45)  # Rotate x-axis labels for readability
    plt.grid(axis='y', linestyle='--', alpha=0.6)  # Grid lines for y-axis
    plt.tight_layout()  # Ensure the layout fits in the figure
    plt.savefig(os.path.join("..", "res", "avg_packet_size.png"), dpi=300, bbox_inches='tight')  # Save the figure
    plt.close()  # Close the plot to free memory


# Function to plot average TTL for all captures
def plot_avg_ttl(capture_names, avg_ttls):
    os.makedirs(os.path.join("..", "res"), exist_ok=True)

    plt.figure(figsize=(12, 4))
    plt.bar(capture_names, avg_ttls, color=CAPTURE_COLORS)
    plt.ylabel("Average TTL")
    plt.title("Average TTL Comparison")
    plt.xticks(rotation=45)
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join("..", "res", "avg_ttl.png"), dpi=300, bbox_inches='tight')
    plt.close()


# Function to plot protocol distribution (TCP/UDP) comparison
def plot_protocol_distribution(capture_names, protocol_distributions):
    os.makedirs(os.path.join("..", "res"), exist_ok=True)
    num_captures = len(capture_names)
    bar_width = 0.25  # Width for each bar

    tcp_percentages = [dist["TCP"] for dist in protocol_distributions]  # Extract TCP percentages
    udp_percentages = [dist["UDP"] for dist in protocol_distributions]  # Extract UDP percentages

    plt.figure(figsize=(12, 6))
    plt.bar([pos - bar_width for pos in range(num_captures)], tcp_percentages, width=bar_width, label="TCP", color=PROTOCOL_COLORS["TCP"])
    plt.bar(range(num_captures), udp_percentages, width=bar_width, label="UDP", color=PROTOCOL_COLORS["UDP"])

    plt.ylabel("Percentage of Packets (%)")
    plt.title("Protocol Distribution Comparison (TCP/UDP)")
    plt.xticks(range(num_captures), capture_names, rotation=45)
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join("..", "res", "protocols.png"), dpi=300, bbox_inches='tight')
    plt.close()


# Function to plot the most frequent ports and their usage percentages
def plot_most_frequent_ports(capture_names, frequent_ports, usage_percentages):
    os.makedirs(os.path.join("..", "res"), exist_ok=True)
    num_captures = len(capture_names)
    bar_width = 0.2  # Width of the bars
    x = range(num_captures)

    port_labels = [f"Port {i + 1}" for i in range(4)]  # Labels for the top 4 ports

    plt.figure(figsize=(12, 6))

    for i in range(4):  # Loop through the top 4 ports
        bars = plt.bar([pos + i * bar_width for pos in x], [usage_percentages[j][i] for j in range(num_captures)], width=bar_width, label=port_labels[i])

        # Annotate the bars with port numbers and usage percentage
        for j, bar in enumerate(bars):
            height = bar.get_height()
            port_number = frequent_ports[j][i]
            plt.text(bar.get_x() + bar.get_width() / 2, height + 0.1, f"{port_number}", ha='center', va='bottom', fontsize=10, color='black')

    plt.ylabel("Average Usage Percentage (%)")
    plt.title("Comparison of Top 4 Most Frequent Ports For Each Capture")
    plt.xticks(x, capture_names, rotation=45)
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.6)

    plt.tight_layout()
    plt.savefig(os.path.join("..", "res", "ports.png"), dpi=300, bbox_inches='tight')
    plt.close()


# Function to plot TCP window size comparison
def plot_tcp_window_size(capture_names, avg_tcp_window_sizes):
    os.makedirs(os.path.join("..", "res"), exist_ok=True)
    plt.figure(figsize=(12, 4))
    plt.bar(capture_names, avg_tcp_window_sizes, color=CAPTURE_COLORS)
    plt.ylabel("Average TCP Window Size")
    plt.title("Average TCP Window Size Comparison")
    plt.xticks(rotation=45)
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join("..", "res", "window_size.png"), dpi=300, bbox_inches='tight')
    plt.close()


# Function to get TLS version counts from CSV files
def get_tls_version_counts(csv_files):
    tls_counts = {"TLSv1.2": [], "TLSv1.3": []}  # Initialize counts for each TLS version

    for csv_file in csv_files:
        try:
            df = pd.read_csv(csv_file, on_bad_lines='skip')  # Read the CSV file
            tls_versions = df['Protocol'].value_counts()  # Count the occurrences of each protocol version

            tls_counts["TLSv1.2"].append(tls_versions.get("TLSv1.2", 0))  # Append TLSv1.2 count
            tls_counts["TLSv1.3"].append(tls_versions.get("TLSv1.3", 0))  # Append TLSv1.3 count

        except Exception as e:
            print(f"Error processing {csv_file}: {e}")
            # Append zero counts if there is an issue with the file
            tls_counts["TLSv1.2"].append(0)
            tls_counts["TLSv1.3"].append(0)

    return tls_counts


# Function to plot TLS version comparison
def plot_tls_version_comparison(capture_names, tls_counts):
    os.makedirs(os.path.join("..", "res"), exist_ok=True)
    bar_width = 0.2  # Width of the bars
    x = range(len(capture_names))

    plt.figure(figsize=(12, 6))

    # Plot TLSv1.2 and TLSv1.3 bars
    plt.bar([pos - bar_width for pos in x], tls_counts["TLSv1.2"], width=bar_width, label="TLSv1.2", color="seagreen")
    plt.bar(x, tls_counts["TLSv1.3"], width=bar_width, label="TLSv1.3", color="darkorange")

    plt.ylabel("TLS Version Usage Count")
    plt.title("TLS Version Usage Comparison")
    plt.xticks(x, capture_names, rotation=45)
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.6)

    plt.tight_layout()
    plt.savefig(os.path.join("..", "res", "tls_version.png"), dpi=300, bbox_inches='tight')
    plt.close()


# Main function to run the analysis and generate plots
def main():
    # List of pcap files to process
    pcap_files = [
        "firefox.pcapng",
        "google.pcapng",
        "spotify.pcapng",
        "youtube.pcapng",
        "zoom.pcapng"
    ]

    # List of CSV files containing protocol counts
    csv_files = [
        "firefox_csv.csv",
        "google_csv.csv",
        "spotify_csv.csv",
        "youtube_csv.csv",
        "zoom_csv.csv"
    ]

    print("Starting analysis...")

    # Process all captures and get various metrics
    capture_names, avg_packet_sizes, avg_ttls, protocol_distributions, frequent_ports, usage_percentages, avg_tcp_window_sizes = process_all_captures(pcap_files)

    # Generate plots for various metrics
    plot_avg_packet_size(capture_names, avg_packet_sizes)
    print("avg size")
    plot_avg_ttl(capture_names, avg_ttls)
    print("avg ttl")
    plot_protocol_distribution(capture_names, protocol_distributions)
    print("protocols")
    plot_most_frequent_ports(capture_names, frequent_ports, usage_percentages)
    print("ports")
    plot_tcp_window_size(capture_names, avg_tcp_window_sizes)
    print("window size")

    # Get TLS version counts from CSV files
    tls_counts = get_tls_version_counts(csv_files)
    # Plot the TLS version comparison
    plot_tls_version_comparison(capture_names, tls_counts)
    print("TLS version comparison")


# Run the main function when the script is executed
if __name__ == "__main__":
    main()
