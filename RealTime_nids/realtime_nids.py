# import pandas as pd
# import joblib
# import time
# from sklearn.ensemble import RandomForestClassifier

# # === Load pre-trained model and preprocessing tools ===
# model = joblib.load('model/rf_model.pkl')
# scaler = joblib.load('model/scaler.pkl')
# encoders = {
#     'protocol_type': joblib.load('model/protocol_type_encoder.pkl'),
#     'service': joblib.load('model/service_encoder.pkl'),
#     'flag': joblib.load('model/flag_encoder.pkl')
# }

# # === Features used during training ===
# features = [
#     'duration', 'protocol_type', 'service', 'flag',
#     'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent',
#     'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
#     'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
#     'num_shells', 'num_access_files', 'num_outbound_cmds',
#     'is_host_login', 'is_guest_login', 'count', 'srv_count',
#     'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
#     'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
#     'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
#     'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
#     'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
#     'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
#     'dst_host_srv_rerror_rate'
# ]

# # === Real-time Prediction Function ===
# def predict_realtime(file_path):
#     try:
#         df = pd.read_csv(file_path)

#         # Only keep training features
#         df = df[features]

#         # Encode categorical columns
#         for col in ['protocol_type', 'service', 'flag']:
#             df[col] = encoders[col].transform(df[col])

#         # Scale the data
#         X_scaled = scaler.transform(df)

#         # Predict
#         predictions = model.predict(X_scaled)
#         for i, pred in enumerate(predictions):
#             result = "✅ Normal" if pred == 1 else "⚠️ Attack"
#             print(f"[{i+1}] Prediction: {result}")
#     except Exception as e:
#         print(f"Error during prediction: {e}")

# # === Automate: Monitor and Predict from CSV ===
# def watch_csv_for_changes(file_path, interval=10):
#     print(f"📡 Monitoring {file_path} for changes...\n")
#     last_modified = None
#     while True:
#         try:
#             current_modified = time.ctime(os.path.getmtime(file_path))
#             if current_modified != last_modified:
#                 print(f"\n🔄 Detected update in {file_path} - Running prediction...")
#                 predict_realtime(file_path)
#                 last_modified = current_modified
#         except Exception as e:
#             print(f"Waiting for file... {e}")
#         time.sleep(interval)

# # === Entry point ===
# if __name__ == "__main__":
#     import os
#     capture_file = "sample_capture.csv"  # Exported from Wireshark (File > Export Packet Dissections > CSV)
#     watch_csv_for_changes(capture_file)

import pyshark
import pandas as pd
import joblib
import time
from preprocess_utils import extract_features
import os

# Load the trained model and encoders
model = joblib.load('model/random_forest_nids.pkl')
protocol_encoder = joblib.load('model/protocol_type_encoder.pkl')
service_encoder = joblib.load('model/service_encoder.pkl')
flag_encoder = joblib.load('model/flag_encoder.pkl')
scaler = joblib.load('model/scaler.pkl')

# Define columns for the features
columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

# Function to append extracted features to CSV
def append_to_csv(packet_features):
    df = pd.DataFrame([packet_features], columns=columns)
    df.to_csv('sample_capture.csv', mode='a', header=False, index=False)

# Function to monitor file changes
def monitor_csv():
    last_mod_time = os.path.getmtime('sample_capture.csv')
    while True:
        new_mod_time = os.path.getmtime('sample_capture.csv')
        if new_mod_time != last_mod_time:
            print("🔄 Detected update in sample_capture.csv - Running prediction...")
            last_mod_time = new_mod_time
            run_prediction()
        time.sleep(1)

# Function to run prediction on the CSV
def run_prediction():
    try:
        df = pd.read_csv('sample_capture.csv')
        # Ensure it has the expected columns for prediction
        if all(col in df.columns for col in columns):
            features = df[columns].iloc[-1].values.reshape(1, -1)
            # Apply the necessary preprocessing
            features_scaled = scaler.transform(features)
            prediction = model.predict(features_scaled)

            print(f"🚨 Prediction: {'Attack' if prediction == 0 else 'Normal'}")
        else:
            print("Error: Missing expected columns in the CSV.")
    except Exception as e:
        print(f"Error during prediction: {e}")

# Capture packets from network interface and process
def capture_packets(interface='eth0'):
    capture = pyshark.LiveCapture(interface=interface)
    print("📡 Capturing packets...")
    
    for packet in capture.sniff_continuously():
        if 'IP' in packet:
            packet_features = extract_features(packet, protocol_encoder, service_encoder, flag_encoder)
            append_to_csv(packet_features)

if __name__ == "__main__":
    capture_packets()  # Start capturing packets
    monitor_csv()  # Start monitoring the CSV for new data
