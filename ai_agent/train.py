import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import classification_report, confusion_matrix
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
import joblib
import seaborn as sns
import matplotlib.pyplot as plt

print("Starting the ADVANCED model training process...")

# --- 1. Load and Prepare Data ---
columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'class', 'difficulty'
]

# --- MODIFICATION: Using your specified absolute file paths ---
# The 'r' before the string is important. It creates a "raw string" which tells
# Python to treat backslashes as literal characters, preventing errors.
try:
    df_train = pd.read_csv(r'C:\Users\samee\OneDrive\Desktop\ai_agent\NSL_KDD_Train.csv', header=None, names=columns)
    df_test = pd.read_csv(r'C:\Users\samee\OneDrive\Desktop\ai_agent\NSL_KDD_Test.csv', header=None, names=columns)
    print("Successfully loaded training and testing datasets from specified paths.")
except FileNotFoundError as e:
    print(f"Error loading data: {e}")
    print("Please double-check that the file paths are correct and the files exist.")
    exit()

df = pd.concat([df_train, df_test], ignore_index=True)
df = df.drop('difficulty', axis=1)

# --- 2. Preprocessing ---
categorical_cols = ['protocol_type', 'service', 'flag']
df = pd.get_dummies(df, columns=categorical_cols, dtype=float)
joblib.dump(df.columns.drop('class'), 'model_columns.pkl')
df['class'] = df['class'].apply(lambda x: 0 if x == 'normal' else 1)
X = df.drop('class', axis=1)
y = df['class']
scaler = MinMaxScaler()
X = scaler.fit_transform(X)
joblib.dump(scaler, 'scaler.pkl')
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print(f"Data preprocessed and split into training ({X_train.shape[0]} samples) and testing ({X_test.shape[0]} samples).")

# --- 3. ADVANCEMENT: Handle Class Imbalance ---
print("\nCalculating class weights to handle data imbalance...")
class_weights = compute_class_weight('balanced', classes=np.unique(y_train), y=y_train.values)
class_weight_dict = dict(enumerate(class_weights))
print(f"Calculated Class Weights: {class_weight_dict}")

# --- 4. ADVANCEMENT: Define Smart Training Callbacks ---
print("\nDefining smart training callbacks (EarlyStopping, ReduceLROnPlateau)...")
early_stopping = EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True, verbose=1)
reduce_lr = ReduceLROnPlateau(monitor='val_loss', factor=0.2, patience=2, min_lr=0.00001, verbose=1)

# --- 5. Build the Deep Learning Model ---
model = Sequential([
    Dense(128, activation='relu', input_shape=(X_train.shape[1],)), Dropout(0.2),
    Dense(64, activation='relu'), Dropout(0.2),
    Dense(32, activation='relu'),
    Dense(1, activation='sigmoid')
])
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
print("\nDeep Learning model built and compiled."); model.summary()

# --- 6. Train the Model with Advancements ---
print("\nStarting model training with advanced callbacks and class weights...")
history = model.fit(
    X_train, y_train,
    epochs=50, 
    batch_size=64,
    validation_data=(X_test, y_test),
    class_weight=class_weight_dict,
    callbacks=[early_stopping, reduce_lr],
    verbose=1
)
print("\nModel training completed.")

# --- 7. ADVANCEMENT: Detailed Model Evaluation ---
print("\n--- Detailed Model Evaluation ---")
y_pred = (model.predict(X_test) > 0.5).astype(int)
print("\nClassification Report:"); print(classification_report(y_test, y_pred, target_names=['Normal (0)', 'Anomaly (1)']))
print("\nConfusion Matrix:"); cm = confusion_matrix(y_test, y_pred); print(cm)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Predicted Normal', 'Predicted Anomaly'],
            yticklabels=['Actual Normal', 'Actual Anomaly'])
plt.xlabel('Predicted Label'); plt.ylabel('Actual Label'); plt.title('Confusion Matrix Heatmap')
plt.savefig('confusion_matrix.png'); print("\nConfusion matrix plot saved as 'confusion_matrix.png'")

# --- 8. Save the Trained Model ---
model.save('soc_model.h5')
print("\nTraining complete. Robust model saved as 'soc_model.h5'")