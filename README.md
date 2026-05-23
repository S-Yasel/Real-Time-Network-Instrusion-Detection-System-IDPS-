 Step 1: Clone or download the project
git clone https://github.com/autolockr/ml-idps.git
cd ml-idps
# Step 2: Create Python virtual environment
python3 -m venv venv
source venv/bin/activate
# Step 3: Install system packages
sudo apt-get update
sudo apt-get install -y python3-dev libpcap-dev iptables \
net-tools build-essential
# Step 4: Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt
# Step 5: Download NSL-KDD dataset
mkdir -p data
wget -O data/KDDTrain+.csv \
https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt
wget -O data/KDDTest+.csv \
https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt
# Step 6: Train the model
mkdir -p models outputs
python train_model.py
# Expected output: Model saved to models/rf_nslkdd.pkl
# Step 7: Run evaluation
python evaluate_model.py
# Step 8: Start real-time detection (requires root)
sudo venv/bin/python idps_main.py \
--interface eth0 \
--model models/rf_nslkdd.pkl \
--threshold 0.85 \
--alerts /var/log/idps/alerts.json
# Step 9: Test with offline PCAP (no root required)
python idps_main.py \
--pcap samples/test_traffic.pcap \
--model models/rf_nslkdd.pkl
# requirements.txt contents:
# scapy==2.5.0
# pandas==2.2.0
# numpy==1.26.4
# scikit-learn==1.4.0
# imbalanced-learn==0.12.0
# joblib==1.3.2
# matplotlib==3.8.3
# seaborn==0.13.2