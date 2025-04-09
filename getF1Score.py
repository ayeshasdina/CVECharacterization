import os
import json
import re
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix

def extract_data_from_json(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            
            model_name = data.get("metadata", {}).get("model_name", "Unknown")
            noun_group = data.get("metadata", {}).get("noun_group", "Unknown")
            f1_score_macro_avg = data.get("metadata", {}).get("metrics", {}).get("classification_report", {}).get("macro avg", {}).get("f1-score", "N/A")
            
            return model_name, noun_group, f1_score_macro_avg
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None, None, None

def extract_confusion_matrices(directory):
    confusion_matrices = {}
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".json"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        model_name = data.get("metadata", {}).get("model_name", "Unknown")
                        noun_group = data.get("metadata", {}).get("noun_group", "Unknown")
                        confusion_matrix = data.get("metadata", {}).get("metrics", {}).get("confusion_matrix", "N/A")
                        
                        if model_name and noun_group:
                            confusion_matrices[(model_name, noun_group)] = confusion_matrix
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
    
    return confusion_matrices

def scan_json_files(directory):
    results = []
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".json"):
                file_path = os.path.join(root, file)
                match = re.search(r'_(\d+)-shot\.json$', file)
                
                if match:
                    n_shot = match.group(1)
                    model_name, noun_group, f1_score_macro_avg = extract_data_from_json(file_path)
                    
                    if model_name and noun_group:
                        results.append((model_name, noun_group, n_shot, f1_score_macro_avg))
    
    return results

def plot_confusion_matrix(confusion_matrix, class_names, errors_only=False, figsize=(15,6), fontsize=16):
    """
    Plots confusion matrix as a color-encoded Seaborn heatmap. Zeroes are
    colored white. Normalized values that are zero when rounded to three
    decimals, Ex. 0.000, will be colored white. Get more decimals by
    updating fmt, for example to '0.4f', and updating get_text() value.
    
    Arguments:
    - confusion_matrix: numpy.ndarray
        The numpy.ndarray object sklearn.metrics.confusion_matrix.
    - class_names: list
        List of class names in the order they index the confusion matrix.
    - figsize: tuple
        The width and height of the figure. Defaults to (15,6).
    - fontsize: int
        Font size for axes labels. Defaults to 16.
    """
    # Instantiate Figure
    fig, (ax1, ax2) = plt.subplots(nrows=1, ncols=2, figsize=figsize)
    plt.subplots_adjust(wspace=0.5)
    
    # Show errors only by filling diagonal with zeroes
    if errors_only:
        np.fill_diagonal(confusion_matrix, 0)        
        
    # Normalize Confusion Matrix
    conf_matrix_norm = confusion_matrix.astype('float') / confusion_matrix.sum(axis=1)[:, np.newaxis]
    conf_matrix_norm = np.nan_to_num(conf_matrix_norm)  # Fix NaNs from zero row total
    df_cm_norm = pd.DataFrame(conf_matrix_norm, index=class_names, columns=class_names)
    
    sns.heatmap(df_cm_norm, ax=ax1, cmap='Blues', fmt='.3f', annot=True, annot_kws={"size": fontsize},
                linewidths=2, linecolor='black', cbar=False)
    
    ax1.set_xlabel('PREDICTED CLASS', fontsize=fontsize, color='black')
    ax1.set_ylabel('TRUE CLASS', fontsize=fontsize, color='black')
    ax1.set_title('Confusion Matrix - Normalized', pad=15, fontsize=fontsize, color='black')
    
    # Confusion Matrix - Raw Counts
    df_cm = pd.DataFrame(confusion_matrix, index=class_names, columns=class_names)
    sns.heatmap(df_cm, ax=ax2, cmap='Blues', fmt='d', annot=True, annot_kws={"size": fontsize+4},
                linewidths=2, linecolor='black', cbar=False)   
    
    ax2.set_xlabel('PREDICTED CLASS', fontsize=fontsize, color='black')
    ax2.set_ylabel('TRUE CLASS', fontsize=fontsize, color='black')
    ax2.set_title('Confusion Matrix - Class Counts', pad=15, fontsize=fontsize, color='black')    
  
    plt.show()

def extract_confusion_matrices(directory):
    """
    Extract confusion matrices from JSON files in a directory.
    
    Returns:
    - confusion_matrices: dict
        Dictionary where keys are (model_name, noun_group) tuples, and values are confusion matrices.
    """
    confusion_matrices = {}
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".json"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        model_name = data.get("metadata", {}).get("model_name", "Unknown")
                        noun_group = data.get("metadata", {}).get("noun_group", "Unknown")
                        confusion_matrix_data = data.get("metadata", {}).get("metrics", {}).get("confusion_matrix", None)
                        
                        if model_name and noun_group and confusion_matrix_data:
                            confusion_matrices[(model_name, noun_group)] = np.array(confusion_matrix_data)
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
    
    return confusion_matrices


def main():
    base_directory = "finalFolderData"  # Update this if the folder is located elsewhere
    extracted_data = scan_json_files(base_directory)
    confusion_matrices = extract_confusion_matrices(base_directory)
    
    print("Model Name | Noun Group | N-Shot | Macro Avg F1-Score")
    print("------------------------------------------------------")
    for model_name, noun_group, n_shot, f1_score_macro_avg in extracted_data:
        f1_score_str = f"{f1_score_macro_avg:.4f}" if isinstance(f1_score_macro_avg, (int, float)) else "N/A"
        print(f"{model_name} | {noun_group} | {n_shot}-shot | {f1_score_str}")
    
    print("\nConfusion Matrices:")
    for (model_name, noun_group), matrix in confusion_matrices.items():
        print(f"{model_name} | {noun_group} | Confusion Matrix: \n{matrix}")

if __name__ == "__main__":
    main()

