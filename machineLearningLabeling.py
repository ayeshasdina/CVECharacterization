#This file is used to train to ML models (KNN and NB) and to get metrics based on test data...


import pandas as pd
import numpy as np
import nltk
import string
import re
import time
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import classification_report, confusion_matrix, multilabel_confusion_matrix

# Ensure NLTK resources are downloaded
nltk.download('punkt')
nltk.download('stopwords')

# Define file paths
datasets = {
    "AttackTheater": "nounGroups/AttackTheater.csv",
    "Context": "nounGroups/Context.csv",
    "ImpactMethod": "nounGroups/ImpactMethod.csv",
    "LogicalImpact": "nounGroups/LogicalImpact.csv",
    "Mitigation": "nounGroups/Mitigation.csv"
}

# Store results for summary
results = {}


def ordered_split(X, y, train_ratio=0.6):
    """
    Splits data into training and testing sets while maintaining the original order.
    """
    split_index = int(X.shape[0] * train_ratio)
    X_train, X_test = X[:split_index], X[split_index:]
    y_train, y_test = y.iloc[:split_index], y.iloc[split_index:]
    return X_train, X_test, y_train, y_test


# Text Preprocessing Function
def preprocess_text(text):
    if not isinstance(text, str):
        return ""
    text = text.lower()  # Convert to lowercase
    text = re.sub(r'\d+', '', text)  # Remove numbers
    text = text.translate(str.maketrans("", "", string.punctuation))  # Remove punctuation
    tokens = word_tokenize(text)  # Tokenize
    tokens = [word for word in tokens if word not in stopwords.words("english")]  # Remove stopwords
    stemmer = PorterStemmer()
    tokens = [stemmer.stem(word) for word in tokens]  # Stemming
    return " ".join(tokens)


# Loop through each dataset
for dataset_name, file_path in datasets.items():
    print(f"\n===== Running ML Models for: {dataset_name} =====")

    # Load Data
    df = pd.read_csv(file_path)

    # Apply Preprocessing to Text Data
    df["Processed_Description"] = df["CVEDescription"].apply(preprocess_text)

    # Feature Extraction using TF-IDF
    vectorizer = TfidfVectorizer()
    X = vectorizer.fit_transform(df["Processed_Description"])
    y = df["Characterization"]

    # Train-Test Split
    X_train, X_test, y_train, y_test = ordered_split(X, y, train_ratio=0.6)

    # Initialize models
    models = {
        "MultinomialNB": MultinomialNB(),
        "KNN": KNeighborsClassifier(n_neighbors=5)  # You can adjust k
    }

    # Train and Evaluate each model
    dataset_results = {}

    for model_name, model in models.items():
        print(f"\nTraining {model_name} for {dataset_name}...")
        model.fit(X_train, y_train)

        # Predict on Test Data
        y_pred = model.predict(X_test)

        # Evaluate Model Performance
        report = classification_report(y_test, y_pred, output_dict=True)
        c_matrix = confusion_matrix(y_test, y_pred)
        macro_f1 = report["macro avg"]["f1-score"]  # Extract macro F1-score

        # Store results
        dataset_results[model_name] = {
            "macro_f1": macro_f1
        }

        print(f"\nConfusion Matrix for {model_name} on {dataset_name}:\n")
        print(c_matrix)  # Print Confusion Matrix

        print(f"{model_name} Macro F1-score for {dataset_name}: {macro_f1:.2f}")

    results[dataset_name] = dataset_results

# Print Summary Report
print("\n===== Summary of Model Performance Across Datasets =====")
for dataset_name, dataset_results in results.items():
    for model_name, result in dataset_results.items():
        print(f"Dataset: {dataset_name}, Model: {model_name}, Macro F1-score: {result['macro_f1']:.4f}")

