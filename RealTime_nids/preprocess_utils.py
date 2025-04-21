# import pandas as pd
# from sklearn.preprocessing import StandardScaler, LabelEncoder
# import joblib

# def load_preprocessors(path='model/'):
#     return {
#         'model': joblib.load(path + 'random_forest_nids_model.pkl'),
#         'scaler': joblib.load(path + 'scaler.pkl'),
#         'protocol_type': joblib.load(path + 'protocol_type_encoder.pkl'),
#         'service': joblib.load(path + 'service_encoder.pkl'),
#         'flag': joblib.load(path + 'flag_encoder.pkl'),
#     }

# def preprocess_packet_df(df, encoders, scaler, feature_columns):
#     # Encode categorical
#     for col in ['protocol_type', 'service', 'flag']:
#         if col in df.columns:
#             df[col] = df[col].apply(lambda x: x if x in encoders[col].classes_ else encoders[col].classes_[0])
#             df[col] = encoders[col].transform(df[col])

#     # Fill missing numeric columns with 0
#     df = df.fillna(0)

#     # Reorder and scale
#     df = df[feature_columns]
#     df_scaled = scaler.transform(df)
#     return df_scaled

def extract_features(packet, protocol_encoder, service_encoder, flag_encoder):
    # Example feature extraction logic for packet
    features = {}
    
    # Convert the features based on your defined logic, e.g., extracting 'protocol_type', 'service', 'flag' etc.
    features['duration'] = packet.sniff_time  # Modify based on your feature extraction
    features['protocol_type'] = protocol_encoder.transform([packet.highest_layer])[0]
    features['service'] = service_encoder.transform([packet.transport_layer])[0]
    features['flag'] = flag_encoder.transform([packet.flag_str])[0]
    features['src_bytes'] = int(packet.length)
    features['dst_bytes'] = int(packet.length)
    
    # Add more features as necessary, matching the columns you trained on
    # This is a simplified version. You should include all the necessary feature extraction logic here
    
    return features
