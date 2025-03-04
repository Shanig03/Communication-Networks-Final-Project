# README: Network Communications Final Project #
This project comprises two independent tasks related to network traffic analysis and machine learning. Each task is described separately below.

### 1. Network Traffic Analysis and Visualization ###
This section involves processing PCAPNG files, analyzing network traffic characteristics, and visualizing the results using Python. The goal is to extract and analyze key metrics from captured network traffic data.

#### Features: ####
**Average Packet Size:** Calculates the average packet size for each capture.

**Average TTL:** Computes the average TTL (Time to Live) for packets.

**Protocol Distribution:** Analyzes the distribution of TCP and UDP traffic within each capture.

**Frequent Ports:** Identifies the most commonly used ports in each capture.

**Port Usage Percentage:** Measures the percentage of packets sent through the most frequent ports.

**TCP Window Size:** Computes the average TCP window size for each capture.

**TLS Version Analysis:** Analyzes and compares the usage of different TLS versions (TLSv1.2 and TLSv1.3) based on traffic data from CSV files.
#### Steps: ####
**PCAPNG File Processing:** The process_all_captures() function processes each PCAPNG file to extract key metrics like packet size, TTL, protocol distribution, and frequent ports.

**Plotting:** The results are visualized in various bar charts:
Average Packet Size Comparison,
Average TTL Comparison,
Protocol Distribution Comparison,
Frequent Ports Comparison,
TCP Window Size Comparison,
TLS Version Comparison (for CSV data).
#### Required Libraries: ####
**scapy:** For reading and processing PCAPNG files.

**matplotlib:** For plotting the results.

**pandas:** For handling data and generating CSV output.

```bash
pip install pandas scapy matplotlib
````


#### How to Run: ####
Make sure you have PCAPNG files (e.g., firefox.pcapng, google.pcapng, etc.) in the same directory (src directory).
Run the script. The analysis will generate various plots saved in the res/ directory.
Additionally, for TLS version comparison, ensure you have CSV files that contain the protocol information.
### 2. Application Prediction using Random Forest ###
This section applies machine learning to predict the application generating network traffic based on packet features. The model uses traffic data, including flow ID, packet size, and timestamp, to predict the correct application.

#### Features: ####
**Flow ID:** A unique identifier for each flow based on the 5-tuple (source IP, destination IP, source port, destination port, and protocol).

**Packet Size:** The size of each packet.

**Timestamp and Time Difference:** The timestamp of each packet and the time difference from the previous packet.

**Protocol:** The transport layer protocol (TCP/UDP).
#### Model Details: ####
Random Forest Classifier is used for the classification task.
The task is evaluated under two conditions:

**Option 1:** Using FlowID, packet size, and timestamp features.

**Option 2:** Using only packet size and timestamp features.

The accuracy of both models is compared, and a bar chart is generated showing the predicted vs. actual application usage.

#### Steps: ####
**PCAPNG to CSV Conversion:** The convert_pcapng_to_csv() function extracts packet-level features from the PCAPNG files and converts them into a CSV format.

**Data Preprocessing:** Features like FlowID and Protocol are processed, with FlowID being label-encoded for machine learning.

**Model Training:** A Random Forest model is trained for both feature sets (with and without FlowID).

**Evaluation:** The models are evaluated using accuracy scores, and the results are visualized in a bar chart comparing the predicted applications against the actual ones.

#### Required Libraries: ####
**pyshark:** For processing PCAPNG files and extracting packet-level features.

**pandas:** For handling data and preparing the dataset.

**matplotlib:** For plotting the results.

**scikit-learn:** For machine learning (Random Forest Classifier and data splitting).

```bash
pip install pyshark pandas numpy matplotlib scikit-learn
```
#### How to Run: ####
Place your PCAPNG files (e.g., firefox.pcapng, google.pcapng, etc.) in the src directory.
The script will automatically process the files and save the merged dataset as merged_data.csv in the output directory.
The model will be trained and evaluated, and the results will be displayed in a bar chart.
#### Output: ####
**Network Traffic Analysis:** The script will output several PNG files with the following plots:
Average Packet Size,
Average TTL,
Protocol Distribution,
Top Ports and their Usage Percentages,
TCP Window Size Comparison,
TLS Version Comparison (from CSV).

**Machine Learning Prediction:** A bar chart showing the comparison between actual and predicted application usage under the two conditions (with and without FlowID).

### 3. Bonus: Application Prediction Using Random Forest

This section demonstrates how machine learning (Random Forest) is applied to predict the application generating network traffic that works together, based on packet features.

#### Code Explanation:
- **Imports**: Necessary libraries for data manipulation (`pandas`, `numpy`), plotting (`matplotlib`), PCAPNG processing (`pyshark`), machine learning (`scikit-learn`), and others for handling IP addresses and directories.
  
- **`classify_network_service`**: Classifies network flows based on predefined IP ranges for services like Spotify and Gmail.
  
- **`extract_and_process_pcap`**: Processes PCAPNG files, extracts packet details (timestamp, size, protocol, IPs), and classifies each flow into services.
  
- **`preprocess_network_data`**: Loads and preprocesses the data, encodes categorical values, and filters out unknown services.
  
- **`train_and_evaluate_model`**: Splits the data into training and testing sets, applies a Random Forest Classifier, and balances the training data using oversampling.
  
- **`assess_model_performance`**: Evaluates the model, calculates accuracy, and saves actual vs. predicted results.
  
- **`visualize_comparison`**: Creates a bar chart comparing actual and predicted application usage.

#### How to Run:
1. Ensure the required libraries are installed:
   ```bash
   pip install pyshark pandas numpy matplotlib scikit-learn imbalanced-learn
   
2. Make sure the capture spotify_with_gmail.pcapng ia in the src directory.
## Conclusion: ##
This project provides both an analytical and a machine learning approach to understanding and predicting network traffic characteristics and behaviors. The first part is aimed at visualizing network traffic metrics, while the second part uses Random Forest to predict the application generating the traffic based on packet features.
