import os
import time
import json
import pandas as pd
from openai import RateLimitError
import re

def format_time(seconds: float) -> str:
    """Return a time string in HH:MM:SS.ss format."""
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = (seconds % 60)
    return f"{hours:02d}:{minutes:02d}:{secs:05.2f}"

def saveData(df, model_name, noun_group, n_shot_number):
    # Format timestamp for file naming
    timestamp = time.strftime("%B_%d_%Y_%I%M%p")
    
    # File name
    filename = f"{timestamp}_{model_name}_{noun_group}_{n_shot_number}.csv"
    
    # Primary save location in output/
    output_path = os.path.join("output", filename)
    df.to_csv(output_path, index=False)
    print(f"Data saved to {output_path}")

    # Additional save location in finalFolderData/{n_shot_number}/{model_name}/
    final_save_dir = os.path.join("finalFolderData", f"{n_shot_number}_shot", model_name)
    os.makedirs(final_save_dir, exist_ok=True)  # Ensure directory exists
    final_output_path = os.path.join(final_save_dir, filename)
    
    df.to_csv(final_output_path, index=False)
    print(f"Data also saved to {final_output_path}")

def save_json(df, metrics, model_name, noun_group, elapsed_timedelta, n_shot_number):
    # Format timestamp for file naming
    timestamp = time.strftime("%B_%d_%Y_%I%M%p")

    # JSON data structure
    data = {
        "metadata": {
            "timestamp": timestamp,
            "model_name": model_name,
            "total_samples": len(df),
            "noun_group": noun_group,
            "elapsed_time": elapsed_timedelta,
            "metrics": metrics  # Store the entire metrics dictionary
        },
        "data": df.to_dict(orient='records')  # Convert DataFrame to list of dicts
    }

    # File name
    json_filename = f"{timestamp}_{model_name}_{noun_group}_{n_shot_number}.json"

    # Primary save location in json_output/
    json_output_path = os.path.join("json_output", json_filename)
    with open(json_output_path, "w") as f:
        json.dump(data, f, indent=4)
    # print(f"JSON results saved to {json_output_path}")

    # Additional save location in finalFolderData/{n_shot_number}_shot/{model_name}/
    final_json_dir = os.path.join("finalFolderData", f"{n_shot_number}_shot", model_name)
    os.makedirs(final_json_dir, exist_ok=True)  # Ensure directory exists
    final_json_path = os.path.join(final_json_dir, json_filename)

    with open(final_json_path, "w") as f:
        json.dump(data, f, indent=4)
    print(f"JSON results also saved to {final_json_path}")


def save_multi_labeled_data(input_csv, output_json, noun_group):
    # Read the CSV file into a DataFrame
    df = pd.read_csv(input_csv, header=None, names=['Description', 'Label'])

    # Drop rows where 'Description' is empty, just whitespace, or a known placeholder
    invalid_descriptions = {"", " ", "CVEDescription"}  # Add any other placeholders as needed
    df = df[~df['Description'].str.strip().isin(invalid_descriptions)]

    # Define label lists based on noun_group
    mitigation_labels = ['ASLR', 'HPKP/HSTS', 'MultiFactor Authentication', 'Physical Security', 'Sandboxed']
    logical_impact_labels = ['Read', 'Write', 'Resource Removal', 'Service Interrupt', 'Indirect Disclosure', 'Privilege Escalation']

    # Select the appropriate label list
    label_list = logical_impact_labels if noun_group == 'LogicalImpact' else mitigation_labels

    # Create a dictionary to store the result
    result = {}

    # Group by Description and aggregate labels
    grouped = df.groupby('Description')['Label'].apply(list).reset_index()

    # Create the unique keys and boolean values for each description
    for idx, row in grouped.iterrows():
        description = row['Description'].strip()
        labels = row['Label']
        boolean_values = [1 if label in labels else 0 for label in label_list]

        result[idx + 1] = {
            "Description": description,
            "Labels": boolean_values
        }

    # Save the result to a JSON file
    with open(output_json, 'w') as json_file:
        json.dump(result, json_file, indent=4)

    print(f"Data successfully saved to {output_json}")



def process_json_with_predictions(input_json, output_json, getPrompt, model_name, client, noun_group, n_shot_number):
    # Load the input JSON file
    with open(input_json, 'r') as json_file:
        data = json.load(json_file)

    # Iterate through each entry and call getPrompt
    for key, value in data.items():
        print(f"Processing entry {key}")
        description = value["Description"]
        prompt = getPrompt(description, noun_group, False, n_shot_number)
        if prompt == "none":
            print(f"No prompt found")
            return "none", "none"
    
        try:
            response = client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model=model_name,
                temperature=0,
                # top_p=1,
                seed=42,
                top_p=1
            )

            content = response.choices[0].message.content.strip()
            label = content
        
        except RateLimitError as e:
            print("Rate limit reached. Waiting 30 seconds before retrying...")
            time.sleep(62)
            response = client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model=model_name,
                temperature=0,
                # top_p=1,
                seed=42,
                top_p=1
            )

            content = response.choices[0].message.content.strip()
            label = content
            
         # Ensure label starts with '[' and ends with ']'
        match = re.search(r"\[.*?\]", label)  # Find the first valid bracketed list
        if match:
            label = match.group(0)  # Extract the valid portion

        else:
            print(f"Warning: Invalid label format for entry {key}. Defaulting to empty list.")
            label = "[]"  # Default to an empty list if no valid format is found

        # Add the predicted labels to the entry
        value["Predicted Labels"] = label
        print(f"Label: {label}")

    # Save the updated data to the output JSON file
    with open(output_json, 'w') as json_file:
        json.dump(data, json_file, indent=4)

    print(f"Updated data with predictions saved to {output_json}")

def fix_predicted_labels_format(input_json, output_json):
    # Load the JSON file
    with open(input_json, 'r') as json_file:
        data = json.load(json_file)

    # Iterate through the JSON data and fix the Predicted Labels format
    for key, value in data.items():
        if "Predicted Labels" in value:
            # Convert the string representation of a list to an actual list
            if isinstance(value["Predicted Labels"], str):
                value["Predicted Labels"] = json.loads(value["Predicted Labels"])

    # Save the updated JSON data
    with open(output_json, 'w') as json_file:
        json.dump(data, json_file, indent=4)

    print(f"Predicted labels format fixed and data saved to {output_json}")


def csv_to_dataframe(csv_file_path):
    try:
        # Read the CSV file into a DataFrame
        df = pd.read_csv(csv_file_path)
        print("CSV file successfully loaded into a DataFrame.")
        return df
    except FileNotFoundError:
        print(f"Error: The file {csv_file_path} was not found.")
    except pd.errors.EmptyDataError:
        print("Error: The CSV file is empty.")
    except pd.errors.ParserError:
        print("Error: There was a parsing error with the CSV file.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")