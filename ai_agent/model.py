import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
import joblib

print("Starting the model training process...")

# --- 1. Load and Prepare Data ---

# Define the column names for the NSL-KDD dataset
columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'class', 'difficulty'
]

# Load the training data
df_train = pd.read_csv(r"C:\Users\samee\OneDrive\Desktop\ai_agent\NSL_KDD_Test.csv", header=None, names=columns)
df_test = pd.read_csv(r"C:\Users\samee\OneDrive\Desktop\ai_agent\NSL_KDD_Test.csv", header=None, names=columns)

# Combine for preprocessing
df = pd.concat([df_train, df_test], ignore_index=True)

# Drop the 'difficulty' column as it's not needed for classification
df = df.drop('difficulty', axis=1)

# Identify categorical and numerical columns
categorical_cols = ['protocol_type', 'service', 'flag']
numerical_cols = df.select_dtypes(include=np.number).columns.tolist()

print(f"Identified {len(categorical_cols)} categorical and {len(numerical_cols)} numerical columns.")

# --- 2. Preprocessing ---

# a) One-Hot Encode Categorical Features
df = pd.get_dummies(df, columns=categorical_cols, dtype=float)
print("Categorical features one-hot encoded.")

# Save the column order and names after one-hot encoding for the app
# This is CRITICAL for consistent predictions
joblib.dump(df.columns.drop('class'), 'model_columns.pkl')
print("Model columns saved to model_columns.pkl")


# b) Encode the Target Label ('class')
# We will create a binary classification: 0 for 'normal', 1 for 'anomaly'
df['class'] = df['class'].apply(lambda x: 0 if x == 'normal' else 1)
print("Target label 'class' encoded to binary (0: normal, 1: anomaly).")

# c) Scale Numerical Features
# We separate the target variable before scaling
X = df.drop('class', axis=1)
y = df['class']

# Fit the scaler ONLY on the training data part of the numerical columns to avoid data leakage
# For simplicity in this script, we'll fit on all numerical columns of X, which is a common practice.
scaler = MinMaxScaler()
X = scaler.fit_transform(X)

# Save the scaler for use in the Streamlit app
joblib.dump(scaler, 'scaler.pkl')
print("Scaler saved to scaler.pkl")

# d) Split the data for training and evaluation
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print(f"Data split into training ({X_train.shape[0]} samples) and testing ({X_test.shape[0]} samples).")

# --- 3. Build the Deep Learning Model ---

model = Sequential([
    # Input layer - The shape must match the number of features
    Dense(128, activation='relu', input_shape=(X_train.shape[1],)),
    Dropout(0.2), # Dropout layer to prevent overfitting
    
    # Hidden Layer
    Dense(64, activation='relu'),
    Dropout(0.2),
    
    # Hidden Layer
    Dense(32, activation='relu'),
    
    # Output Layer - Sigmoid for binary classification (outputs a probability)
    Dense(1, activation='sigmoid')
])

# Compile the model
model.compile(optimizer='adam',
              loss='binary_crossentropy', # Perfect loss function for binary classification
              metrics=['accuracy'])

print("Deep Learning model built and compiled.")
model.summary()

# --- 4. Train the Model ---

print("Starting model training...")
history = model.fit(X_train, y_train,
                    epochs=100, # For a hackathon, 10-20 epochs is good. For production, more.
                    batch_size=64,
                    validation_split=0.1,
                    verbose=1)
print("Model training completed.")

# --- 5. Evaluate the Model ---

loss, accuracy = model.evaluate(X_test, y_test)
print("\n--- Model Evaluation ---")
print(f"Test Accuracy: {accuracy*100:.2f}%")
print(f"Test Loss: {loss:.4f}")

# --- 6. Save the Trained Model ---

model.save('soc_model.h5')
print("\nTraining complete. Model saved as 'soc_model.h5'")