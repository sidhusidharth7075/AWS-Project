# AMS-Project


# 🏥 MedTrack - Healthcare Appointment & Notification System

MedTrack is a Flask-based web application designed for managing healthcare appointments with AWS integration. It allows users to register, book appointments, receive email and SMS notifications, and stores all user and appointment data securely using **Amazon DynamoDB** and **Amazon SNS**.



## .env file

```bash
FLASK_SECRET_KEY=your_secret_key
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
USERS_TABLE=MedTrack_Users
APPOINTMENTS_TABLE=MedTrack_Appointments
NOTIFICATIONS_TABLE=MedTrack_Notifications
SMTP_EMAIL=youremail@example.com
SMTP_PASSWORD=your_email_password
SNS_TOPIC_ARN=arn:aws:sns:ap-south-1:xxxxxxxxxxxx:your-topic-name
```



## 🛠️ Installation

```bash
python --version
python 3.10.11 # minimum 
```

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/AWS-Project.git
cd AWS-Project
```

### 2. Create and Activate a Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\scripts\Activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Server
```bash
python app.py
```

### 5. Access the Website
- not published yet.





## 📧 Contact
For inquiries or collaboration opportunities, reach out via:
- Email: [sidhusidharth7075@gmail.com](mailto:sidhusidharth7075@gmail.com)
- LinkedIn: [LohithSappa](https://www.linkedin.com/in/lohith-sappa-aab07629a/)

---
## ⭐ Don't forget to **star** this repository if you found it helpful!


