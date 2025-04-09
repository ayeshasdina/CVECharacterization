#This file is a test where you send prompts to local llama3.1 on computer.
#NOTE: THis file was tested early on, but not used to test all noun groups due to poor performance on initial noun group test for attackTheater... Would work better if Llama3.1 405 is running local. 

import pandas as pd
from langchain_ollama import OllamaLLM

from prompts.prompts import cve_definition, a_theatre_desc, a_theatre_definition, questions_to_be_answered, example_cve_with_labels
from utilities.saveMetrics import get_accuracy, evaluate_classification
from utilities.saveData import saveData, save_json

model_name = "llama3.1"

# Initialize the Llama3.1 model
llama_model = OllamaLLM(model=model_name)

# Initialize the call count for get_labels
get_labels_call_count = 0


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

# cve_definition, a_theatre_desc, a_theatre_definition
def get_labels(description): 
    global get_labels_call_count
    get_labels_call_count += 1
    # Construct the prompt
    cve_description = str(description)
    # Uncomment below prompt for '73 accurate one'. 
    prompt = (
        f"You are an expert in classifying CVE (Common Vulnerabilities and Exposures) based on detailed descriptions. "
        f"Below are some definitions and descriptions to guide you:\n\n"
        f"CVE Definition: {cve_definition}\n"
        f"Attack Theatre Description: {a_theatre_desc}\n"
        f"Attack Theatre Definition: {a_theatre_definition}\n\n"
        f"Here is the CVE description for you to classify: {cve_description}\n"
        # f"Your task is to label the CVE description with one or more labels from the Attack Theatre VDO noun group. "
        f"Your task is to label the CVE description with the most relevant Attack Theatre Vector label. "
        f"Evaluate each Attack Theatre Vector label to determine if the CVE description falls under that category (e.g., Remote, Limited Rmt, Local, Physical). "
        # f"Your final output should be a comma-separated list of all applicable VDO labels, or a single label if only one applies. "
        f"Your final output should be the label that best characterizes the CVE description. (e.g. Remote, Limited Rmt, Local, Physical)"
        f"Do not provide any additional output aside from the label(s). "
        
        f"Remember, return ONLY the label name. Do not explain your reasoning or provide any other output. Don't even add a period after the label."
        # f"Ask yourself the following questions to help you come up with your final response: {questions_to_be_answered}"
        # f"Remember, return ONLY the label name(s) as a comma-separated list if more than one applies. Do not explain your reasoning or provide any other output."
    )

    # Invoke the model with the prompt

    # Uncomment two lines below to use the model
    response = llama_model.invoke(input=prompt)
    label = response.strip()

    #comment below line out to use the model
    # label = "Remote"
    # Ask the model for reasoning
    reasoning_prompt = (
        f"Given the following CVE description: {cve_description}\n"
        f"and the label you selected: {label}\n"
        f"Explain in 2 sentences or less why the label '{label}' is the most relevant label for the CVE description given. Give nothing aside from your reasoning in your response."
    )
    # Uncomment two lines below to use the model
    # reasoning_response = llama_model.invoke(input=reasoning_prompt)
    # reasoning = reasoning_response.strip()

    #Comment below line out to use the model
    reasoning = "This is my reasoning bruh"
    
    return label, reasoning
    

def add_labels(df):
    labeled_data = []
    output_count = 1

    for index, row in df.iterrows():
        cve_description = row['CVE Description']
        characterization = row['Characterization']
        label, reasoning = get_labels(cve_description)
        
        labeled_data.append({
            'CVE Description': cve_description,
            'theirLabels': characterization,
            'ourLabels': label,
            'modelReasoning': reasoning
        })

        if (index + 1) % 15 == 0:
            temp_df = pd.DataFrame(labeled_data)
            current_accuracy = get_accuracy(temp_df)
            print(f"Current accuracy after {index + 1} rows: {current_accuracy:.2f}%")
            output_filename = f'output{output_count}.csv'
            temp_df.to_csv(output_filename, index=False)
            print(f"Data saved to {output_filename}")
            output_count += 1

    return pd.DataFrame(labeled_data)


if __name__ == "__main__":
    # Specify the path to your CSV file
    #For this test, I'm gonna feed it the AttackTheatre.csv file. 
    csv_file_path = 'nounGroups/AttackTheater.csv'
    
    # # Convert the CSV to a DataFrame
    df = csv_to_dataframe(csv_file_path)
    # # Add labels to the DataFrame
    labeled_df = add_labels(df)
    # output_file_path = 'trainDataVSLLMcharacterization.csv'
    # labeled_df = csv_to_dataframe(output_file_path)
    # Calculate and print the accuracy
    accuracy = get_accuracy(labeled_df)
    print(f"According to my original accuracy function, the accuracy is {accuracy:.2f}%\n\n")
    # Calculate and print the accuracy, precision, recall, and F1-score
    metrics = evaluate_classification(labeled_df)
    print("Now using sklearn's metrics, the accuracy is: \n")
    print(metrics)
    
    saveData(labeled_df, model_name)
    # Write the new DataFrame to a CSV file
    # labeled_df.to_csv('fullLabeledDataOutputWithGPT4o.csv', index=False)
    # print("Labeled data has been written to trainDataVSLLMcharacterization.csv")
    

    # Save JSON
    save_json(labeled_df, metrics, model_name)


    # # If successful, print the DataFrame
    if labeled_df is not None:
        print(labeled_df.head())
        print(labeled_df.shape)