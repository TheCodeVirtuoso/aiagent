

# Neo SOC Agent: The Autonomous AI Analyst

An advanced, agentic AI platform designed to autonomously triage security alerts, detect both known and zero-day threats, and provide comprehensive, AI-generated incident reports. This project was developed for the "Agentic AI" hackathon theme.

![Neo SOC Agent Demo](demo.gif)

## 🚀 Key Features

*   **🛡️ Hybrid AI Detection Engine:** Combines a supervised model ("Known Threat Expert") and an unsupervised autoencoder ("Zero-Day Specialist") for robust threat detection against both known and novel attacks.
*   **🤖 Adaptive Agent Orchestration:** Dynamically summons a specialized 'task force' of virtual agents (e.g., Network Agent, Threat Intel Agent) based on alert characteristics, moving beyond rigid playbooks.
*   **📝 Generative AI Summaries:** Features an "AI Scribe Agent" that generates full, human-readable executive summaries for complex incidents in a single click, transforming minutes of work into seconds.
*   **🌐 MITRE ATT&CK® Framework Mapping:** Automatically enriches alerts with industry-standard tactical context, providing immediate insight into an attacker's objectives.
*   **🕸️ Threat Investigation Graph:** Visualizes the relationships between high-risk threats, services, and tactics in a dynamic campaign map, helping analysts see the "big picture."
*   **🌍 Geospatial Threat Map:** Plots the simulated origins of high-risk attacks on a live, interactive world map.
*   **🧠 Human-in-the-Loop Feedback:** Includes a simulated reinforcement learning loop where analyst feedback improves model confidence over time.

## ⚙️ Technology Stack

*   **Backend:** Python
*   **Machine Learning:** TensorFlow/Keras, Scikit-learn
*   **Data Processing:** Pandas, NumPy
*   **Dashboard & UI:** Streamlit, Plotly
*   **Database:** MySQL (connected via SQLAlchemy)
*   **Configuration:** python-dotenv

## 🏛️ Project Architecture

A simplified overview of the project's workflow.

[NSL-KDD CSV Data] -> [Advanced Training Pipeline (train_*.py)] -> [Saved AI Models (.h5, .pkl)]
|
v
[MySQL Database (setup_database.py)] -> [Streamlit Application (app.py)] -> [Hybrid AI Engine] -> [Interactive SOC Dashboard]
|
v
[Analyst Feedback] -> [Logs to DB]


## 🛠️ Setup and Installation

Follow these steps to get the project running locally.

### 1. Clone the Repository
Clone this project to your local machine.

### 2. Install Dependencies
It's highly recommended to use a Python virtual environment. Install all required libraries using the `requirements.txt` file.

bash
# Navigate to the project directory
cd path/to/your/project_folder

# Create and activate a virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

# Install all dependencies
pip install -r requirements.txt
3. Set Up MySQL Database

Ensure you have a MySQL server running. Create a new, empty database for this project (e.g., soc_agent_db).

4. Configure Environment Variables

In the project's root directory, create a file named .env. Copy the content from .env.example into it and update the DATABASE_URL with your actual MySQL database connection details.

# .env file
# Format: dialect+driver://username:password@host:port/database_name
DATABASE_URL="mysql+mysqlconnector://your_username:your_password@localhost:3306/your_database_name"
▶️ How to Run

Execute the scripts from your terminal in the following order, ensuring you are in the project's root directory.

1. Train the Supervised Model

This script trains the primary "Known Threat" detector and creates soc_model.h5, scaler.pkl, and model_columns.pkl.

python train_model.py
2. Train the Unsupervised Model

This script trains the "Zero-Day" detector (Autoencoder) and creates autoencoder_model.h5.
python train_autoencoder.py
3. Set Up and Populate the Database
This script connects to your MySQL database, creates the necessary tables, and ingests the data from the CSV file. You only need to run this script once.
python setup_database.py
4. Launch the Application
Start the Streamlit application. Your browser should open automatically.
streamlit run app.py
📁 Project Structure

A brief overview of the key files in this project.
.
├── app.py                  # The main Streamlit application with all UI and logic.
├── train_model.py          # Script to train the primary supervised detection model.
├── train_autoencoder.py    # Script to train the unsupervised zero-day detection model.
├── setup_database.py       # Script to initialize and populate the MySQL database.
├── requirements.txt        # A list of all project dependencies for pip.
├── .env                    # (You create this) Secure file for your database URL.
├── .env.example            # An example template for the .env file.
├── soc_model.h5            # (Generated) The trained supervised model.
├── autoencoder_model.h5    # (Generated) The trained unsupervised model.
├── scaler.pkl              # (Generated) The data scaler for preprocessing.
├── model_columns.pkl       # (Generated) The feature columns required by the models.
└── README.md               # This file.
🚀 Future Work

Full Reinforcement Learning: Implement the backend for the feedback loop to actually retrain and fine-tune the models based on analyst decisions.
Live Threat Intelligence APIs: Replace the simulated threat intel database with live API calls to services like VirusTotal or AbuseIPDB for real-time enrichment.
SOAR Platform Integration: Build an API endpoint so the agent can send its high-confidence recommendations directly to a SOAR platform (like Cortex XSOAR or Splunk SOAR) for automated execution.
👥 Team Members - Neo Agents
Deepak Bharathwaj S (Leader)
Kanipakam Poojitha
Bammidi Sruthi Sri
T Sameer
🎓 Institution
Amrita Vishwa VidyaPeetham
📜 License
This project is licensed under the MIT License.
