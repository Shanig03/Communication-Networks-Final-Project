import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import pyshark
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import RandomOverSampler
from ipaddress import ip_address, ip_network
import os

# Custom logic for classifying network flows based on IP ranges (obfuscated naming)
def classify_network_service(flow_identifier):
    # Define known IP ranges for Spotify and Gmail services
    spotify_ips = {
        "35.186.224.0/24", "104.199.64.0/18", "34.107.0.0/16",
        "34.120.0.0/16", "35.190.0.0/17", "130.211.0.0/22"
    }
    gmail_ips = {
        "74.125.0.0/16", "172.217.0.0/16", "142.250.0.0/16"
    }

    # Split the flow identifier into source and destination IPs
    source_ip, destination_ip = flow_identifier.split("-")

    def ip_within_range(ip, ip_ranges):
        # Check if an IP is within the given IP range(s)
        return any(ip_address(ip) in ip_network(r) for r in ip_ranges)

    # Classify the service based on whether the source or destination IP falls within known ranges
    if ip_within_range(source_ip, spotify_ips) or ip_within_range(destination_ip, spotify_ips):
        return "Spotify"
    if ip_within_range(source_ip, gmail_ips) or ip_within_range(destination_ip, gmail_ips):
        return "Gmail"
    return "Other"  # Default to 'Other' if no match is found

def extract_and_process_pcap(pcap_file_path, csv_output_path):
    # Open the pcap file and filter for IP packets
    capture = pyshark.FileCapture(pcap_file_path, display_filter="ip")
    packet_details = []

    # Iterate over packets to extract relevant details
    for packet in capture:
        try:
            # Extract timestamp, packet size, protocol, and flow ID
            timestamp = float(packet.sniff_time.timestamp())
            packet_size = int(packet.length)
            protocol = packet.highest_layer

            if hasattr(packet, "ip"):
                # Extract source and destination IPs for flow ID
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                flow_id = f"{src_ip}-{dst_ip}"

                # Add extracted details to packet_details list
                packet_details.append([timestamp, packet_size, protocol, flow_id])
        except AttributeError:
            # Skip packets without IP details
            continue

    capture.close()

    # Convert packet details to a DataFrame for easier manipulation
    df = pd.DataFrame(packet_details, columns=["Timestamp", "Packet_Size", "Protocol", "Flow_ID"])
    # Calculate time gaps between consecutive packets
    df["Time_Gap"] = df["Timestamp"].diff().fillna(0).clip(lower=0)

    # Add the network service classification based on flow ID
    df["Service"] = df["Flow_ID"].apply(classify_network_service)

    # Save the processed data to CSV
    df.to_csv(csv_output_path, index=False)
    print(f"Packet data saved to {csv_output_path}")

def preprocess_network_data(csv_file_path):
    # Load the CSV data into a DataFrame
    data = pd.read_csv(csv_file_path)

    if 'Protocol' in data.columns:
        # Encode the protocol column with numerical labels
        label_encoder = LabelEncoder()
        data['Protocol'] = label_encoder.fit_transform(data['Protocol'])

    # Filter out rows where the service is 'Other'
    data = data[data["Service"] != "Other"]  # Keep only known services
    return data

def train_and_evaluate_model(data):
    # Define features and target for the model
    features = ["Packet_Size", "Time_Gap"]
    target = "Service"

    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(data[features], data[target], test_size=0.2, random_state=42)

    if y_train.nunique() < 2:
        # Ensure that there are at least 2 distinct service labels for training
        raise ValueError(f"Not enough distinct services for training: {y_train.value_counts().to_dict()}")

    # Use RandomOverSampler to balance the training data by oversampling the minority class
    oversampler = RandomOverSampler(random_state=42)
    X_train_balanced, y_train_balanced = oversampler.fit_resample(X_train, y_train)

    # Train a Random Forest model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train_balanced, y_train_balanced)

    return model, X_test, y_test

def assess_model_performance(model, X_test, y_test, results_csv="spotify_with_gmail_results.csv"):
    # Use the trained model to predict on the test set
    predictions = model.predict(X_test)

    # Calculate model accuracy
    accuracy = accuracy_score(y_test, predictions) * 100
    print(f"Model Accuracy: {accuracy:.2f}%")

    # Save the comparison between actual and predicted services to a CSV file
    results_df = pd.DataFrame({
        "Actual_Service": y_test,
        "Predicted_Service": predictions
    })
    results_df.to_csv(results_csv, index=False)
    print(f"Results saved to {results_csv}")

    return y_test, predictions

def visualize_comparison(y_test, y_pred, image_output="spotify_with_gmail_comparison.png"):
    # Get the unique services in the test data
    services = y_test.unique()

    # Calculate the counts of actual and predicted services
    actual_counts = pd.Series(y_test).value_counts().reindex(services, fill_value=0)
    predicted_counts = pd.Series(y_pred).value_counts().reindex(services, fill_value=0)

    # Set up bar chart positions
    x_positions = np.arange(len(services))
    bar_width = 0.35

    # Create the bar plot for actual vs predicted services
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(x_positions - bar_width / 2, actual_counts, bar_width, label="Actual", color="#E07A5F")
    ax.bar(x_positions + bar_width / 2, predicted_counts, bar_width, label="Predicted", color="#81B29A")

    # Set labels, title, and ticks
    ax.set_xlabel("App")
    ax.set_ylabel("Packet Count")
    ax.set_title("Actual vs Predicted App Usage")
    ax.set_xticks(x_positions)
    ax.set_xticklabels(services, rotation=45, ha="right")
    ax.legend()

    # Save the figure to the specified path and display it
    plt.savefig(image_output, dpi=300, bbox_inches="tight")
    plt.show()
    print(f"Visualization saved to {image_output}")

def main():
    # Create the 'res' directory inside the 'Ex5' directory if it doesn't exist
    output_dir = os.path.join(os.getcwd(), "..", "res")
    os.makedirs(output_dir, exist_ok=True)

    # Set file paths for input and output
    pcap_file = "spotify_with_gmail.pcapng"
    csv_output = os.path.join(output_dir, "spotify_with_gmail.csv")
    image_output = os.path.join(output_dir, "spotify_with_gmail_comparison.png")
    results_csv = os.path.join(output_dir, "spotify_with_gmail_results.csv")

    # Extract data from the pcap file and save it to a CSV
    extract_and_process_pcap(pcap_file, csv_output)
    # Preprocess the CSV data to prepare it for training
    data = preprocess_network_data(csv_output)

    if data.empty or data["Service"].nunique() < 2:
        # Check if there are enough valid services to proceed with training
        print("Insufficient valid services for training (at least 2 different services needed).")
        print("Detected services:\n", data["Service"].value_counts())
        return

    # Train and evaluate the model, returning the actual and predicted values
    trained_model, X_test, y_test = train_and_evaluate_model(data)
    actual, predicted = assess_model_performance(trained_model, X_test, y_test, results_csv)
    # Visualize the comparison of actual vs predicted services
    visualize_comparison(actual, predicted, image_output)

if __name__ == "__main__":
    main()
