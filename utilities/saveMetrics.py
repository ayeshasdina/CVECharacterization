#saveMetrics.py
# This file compare our model's labels to the 'ground truth' labels obtained from AttackTheater.csv and calculates important metrics using sklearn.

import json
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.metrics import classification_report, confusion_matrix, multilabel_confusion_matrix

def get_accuracy(df):
    # Count the number of correct matches
    correct_matches = (df['theirLabels'] == df['ourLabels']).sum()
    # Calculate the total number of rows
    total_rows = len(df)
    # Calculate accuracy
    accuracy = (correct_matches / total_rows) * 100
    return accuracy

def evaluate_classification(df):
    y_true = df['theirLabels']
    y_pred = df['ourLabels']

    # Get string-based report if you like
    report_str = classification_report(y_true, y_pred, zero_division=0)

    # Get dict-based report for easy per-class metrics
    report_dict = classification_report(y_true, y_pred, zero_division=0, output_dict=True)

    cm = confusion_matrix(y_true, y_pred)
    accuracy = accuracy_score(y_true, y_pred)

    weighted_precision = precision_score(y_true, y_pred, average='weighted', zero_division=0)
    weighted_recall = recall_score(y_true, y_pred, average='weighted', zero_division=0)
    weighted_f1 = f1_score(y_true, y_pred, average='weighted', zero_division=0)

    return {
        "classification_report_str": report_str,   # (optional) keep the string
        "classification_report": report_dict,
        "confusion_matrix": cm.tolist(),
        "Accuracy (%)": accuracy * 100,
        "Precision": weighted_precision,
        "Recall": weighted_recall,
        "F1-Score": weighted_f1
    }
def custom_confusion_matrix(y_true, y_pred):
    import numpy as np

    num_labels = max(len(t) for t in y_true + y_pred)
    cm = np.zeros((num_labels, 2, 2), dtype=int)

    for true_vec, pred_vec in zip(y_true, y_pred):
        # Pad if needed
        true_vec = list(true_vec) + [0]*(num_labels - len(true_vec))
        pred_vec = list(pred_vec) + [0]*(num_labels - len(pred_vec))
        
        for i in range(num_labels):
            t = true_vec[i]
            p = pred_vec[i]
            if t == 0 and p == 0:
                cm[i, 0, 0] += 1
            elif t == 0 and p == 1:
                cm[i, 0, 1] += 1
            elif t == 1 and p == 0:
                cm[i, 1, 0] += 1
            else:  # t == 1 and p == 1
                cm[i, 1, 1] += 1

    return cm

#Custom funcion to generate cooccurrence matrix.
import numpy as np
def multi_label_cooccurrence_matrix(y_true, y_pred):
    """
    Produce an N x N matrix for multi-label data, where:
      - N is the total number of possible labels (max length seen).
      - Entry (i, j) counts how often label i was in y_true
        while label j was in y_pred, across all samples.
    
    :param y_true: list of lists/arrays of 0/1
    :param y_pred: list of lists/arrays of 0/1
    :return: np.ndarray of shape (N, N)
    """
    # Figure out the max # of labels needed (e.g. 5 vs 6).
    num_labels = max(len(t) for t in y_true + y_pred)
    
    # Initialize N x N matrix
    cooccurrence_mat = np.zeros((num_labels, num_labels), dtype=int)
    
    # Iterate over each sample
    for true_vec, pred_vec in zip(y_true, y_pred):
        # Pad shorter vectors with 0, if needed
        true_vec = list(true_vec) + [0]*(num_labels - len(true_vec))
        pred_vec = list(pred_vec) + [0]*(num_labels - len(pred_vec))
        
        # For each label i that is '1' in ground truth,
        # and each label j that is '1' in predictions,
        # increment the (i, j) cell.
        for i in range(num_labels):
            if true_vec[i] == 1:
                for j in range(num_labels):
                    if pred_vec[j] == 1:
                        cooccurrence_mat[i, j] += 1
    
    return cooccurrence_mat

#This will return metrics for multi-labeled noun groups (i.e. LogicalImpact and Mitigation)
def evaluate_multilabel_classification(input_json, noun_group):
    # Load the JSON file
    with open(input_json, 'r') as json_file:
        data = json.load(json_file)

    # Extract ground truth and predicted labels
    y_true = []
    y_pred = []

    for value in data.values():
        y_true.append(value["Labels"])
        y_pred.append(value["Predicted Labels"])

    # Select the correct label names based on noun_group
    if noun_group == 'LogicalImpact':
        target_names = ['Read', 'Write', 'Resource Removal', 'Service Interrupt', 'Indirect Disclosure', 'Privilege Escalation']
    else:
        target_names = ['ASLR', 'HPKP/HSTS', 'MultiFactor Authentication', 'Physical Security', 'Sandboxed']

    # Compute classification report
    classification_report_dict = classification_report(y_true, y_pred, zero_division=0, target_names=target_names, output_dict=True)

    # Compute other metrics
    multilabel_cm = multi_label_cooccurrence_matrix(y_true, y_pred) #We compute cooccurrence matrix here to show matrix with all labels together to show performance 
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, average='weighted', zero_division=0)
    recall = recall_score(y_true, y_pred, average='weighted', zero_division=0)
    f1 = f1_score(y_true, y_pred, average='macro', zero_division=0)  # Changed to 'macro'

    # Print metrics
    print("Classification Report:")
    print(json.dumps(classification_report_dict, indent=4))
    print(f"Confusion matrix for {input_json}\n")
    print("\nConfusion Matrices:")
    print(multilabel_cm)
    print("\nOverall Metrics:")
    print(f"Accuracy: {accuracy * 100:.2f}%")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1-Score (Macro): {f1:.4f}")

    return {
        "classification_report": classification_report_dict,
        "confusion_matrix": multilabel_cm.tolist(),
        "Accuracy (%)": accuracy * 100,
        "Precision": precision,
        "Recall": recall,
        "F1-Score": f1  # Now using macro instead of weighted
    }