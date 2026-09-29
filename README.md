# AI-Powered Phishing Website Detection and Real-Time Cybersecurity Alert System

Final-year project based on the provided "Phishing URL Detection using Machine Learning Models" mini-project presentation.

## Features
- URL feature extraction
- Random Forest phishing classifier
- Real-time prediction
- Confidence score
- Explainable warning indicators
- Scan history
- SQLite database
- Web dashboard
- Six-model comparison can be added using the same feature matrix

## Technology
Python, Flask, Scikit-learn, Pandas, NumPy, Joblib, HTML, CSS, JavaScript, SQLite.

## Important dataset note
The supplied PPT references a Kaggle phishing website dataset. This package contains a small `data/sample_urls.csv` so the application can run without an external download. For the final academic version, replace it with the full approved dataset and retrain the model.

Do not claim the PPT's 96.9% Random Forest accuracy for this included sample model. Recalculate metrics after training on your final dataset.

## Windows setup

1. Install Python 3.11 or newer.
2. Open Command Prompt in this folder.
3. Create a virtual environment:

   python -m venv venv

4. Activate:

   venv\Scripts\activate

5. Install packages:

   pip install -r requirements.txt

6. Train the model:

   python train_model.py

7. Start the website:

   python app.py

8. Open:
   http://127.0.0.1:5000

## Linux/macOS

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python train_model.py
python app.py

## Project flow

User URL
  -> URL feature extraction
  -> preprocessing
  -> Random Forest
  -> prediction + confidence
  -> explanation
  -> SQLite scan history
  -> dashboard

## Suggested final-year extensions
- Chrome browser extension
- User login
- MySQL instead of SQLite
- SHAP/LIME explanations
- Live domain/SSL checks
- Deployed cloud API
- Admin analytics
