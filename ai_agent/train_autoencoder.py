import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
import joblib

print("--- Starting ADVANCED Autoencoder Training Process ---")

# --- 1. Load Data (Using your specific paths) ---
columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'class', 'difficulty'
]
df_train = pd.read_csv(r'C:\Users\samee\OneDrive\Desktop\ai_agent\NSL_KDD_Train.csv', header=None, names=columns)
df_test = pd.read_csv(r'C:\Users\samee\OneDrive\Desktop\ai_agent\NSL_KDD_Test.csv', header=None, names=columns)
df = pd.concat([df_train, df_test], ignore_index=True)
df = df.drop('difficulty', axis=1)

# --- 2. Preprocessing (Same as before) ---
categorical_cols = ['protocol_type', 'service', 'flag']
df_processed = pd.get_dummies(df, columns=categorical_cols, dtype=float)

# --- 3. CRITICAL STEP: Train ONLY on 'normal' data ---
# This is what makes an autoencoder a powerful anomaly detector.
print("\nIsolating 'normal' traffic for training...")
normal_df = df_processed[df['class'] == 'normal']
X_normal = normal_df.drop('class', axis=1)

# We use the same scaler that the main model used for consistency
scaler = joblib.load('scaler.pkl')
X_normal_scaled = scaler.transform(X_normal)

print(f"Training autoencoder on {len(X_normal_scaled)} 'normal' samples.")

# --- 4. Build the Autoencoder Model ---
input_dim = X_normal_scaled.shape[1]
encoding_dim = 32  # A bottleneck layer to force the model to learn a compressed representation

input_layer = Input(shape=(input_dim,))
# "Encoder" part - compresses the input
encoder = Dense(128, activation="relu")(input_layer)
encoder = Dense(64, activation="relu")(encoder)
encoder = Dense(encoding_dim, activation="relu")(encoder)

# "Decoder" part - tries to reconstruct the original input from the compressed version
decoder = Dense(64, activation='relu')(encoder)
decoder = Dense(128, activation='relu')(decoder)
decoder = Dense(input_dim, activation='sigmoid')(decoder) # Reconstruct back to the original shape

autoencoder = Model(inputs=input_layer, outputs=decoder)
autoencoder.compile(optimizer='adam', loss='mean_squared_error')
print("\nAutoencoder model built and compiled.")
autoencoder.summary()

# --- 5. Train the Autoencoder ---
print("\nStarting autoencoder training...")
autoencoder.fit(X_normal_scaled, X_normal_scaled,
                epochs=20,
                batch_size=64,
                shuffle=True,
                validation_split=0.1,
                verbose=1)
print("Autoencoder training completed.")

# --- 6. Save the Trained Autoencoder ---
autoencoder.save('autoencoder_model.h5')
print("\n✅ Zero-Day Detector (Autoencoder) saved as 'autoencoder_model.h5'")