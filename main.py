import pandas as pd
import time
from datetime import datetime
import os
from dotenv import load_dotenv
from openai import OpenAI
from openai import RateLimitError
import json
# import google.generativeai as genai
#----------------------Load Local Libraries----------------------#
from utilities.saveMetrics import get_accuracy, evaluate_classification, evaluate_multilabel_classification
from utilities.saveData import saveData, save_json, csv_to_dataframe, format_time, save_multi_labeled_data, process_json_with_predictions, fix_predicted_labels_format
from prompts.promptFunctions import getPrompt
#----------------------Load Environment Variables----------------------#
load_dotenv()

#----------------------Model Settings----------------------#
# model_name = "gemini-1.5-flash" #--------------------> Change this to the model you want to test. 
# model_name = "ft:gpt-4o-2024-08-06:personal:attack-theater-experiment:AqwJKGOP"
# model_name = "gemini-1.5-flash"
# model_id = "gemini-1.5-flash"
model_name = "gpt-4o" #NOTE: Change this to test different models...
model_id = "gpt-4o"
# n_shot_number = "0-shot"
# Set this to True if you want to add reasoning to the output. (NOTE: This will use more tokens and be a little slower.)


#----------------------API Key----------------------#
openai_api_key = os.getenv('OPENAI_API_KEY')
client = OpenAI(api_key=openai_api_key) #--------------------> This is the OpenAI client, and can be used with Gemini like this. Uncomment this line if using regular OpenAI. 



#--------------------------------------GOOGLE -> Use this client if you are using gemini and have a google api key, or try running collab with vertex -------------#
# client = OpenAI(
#     api_key=os.getenv("GOOGLE_AI_API_KEY"),
#     base_url="https://generativelanguage.googleapis.com/v1beta/openai/"
# )

# api_key = os.getenv("GOOGLE_AI_API_KEY")
# genai.configure(api_key=api_key)
# googleModel = genai.GenerativeModel(model_name)

add_reasoning = False
#----------------------Call Counts----------------------#
get_labels_call_count = 0



#This function will find correct prompt to send to model based on target noun group and CVE description. Output can be single or comma separated list... Handles noun groups with single labeled output.
def get_labels(description, noun_group): 
    cve_description = str(description)

    # Generate the prompt for the right noun group and cve_description 
    prompt = getPrompt(cve_description, noun_group, add_reasoning, n_shot_number)
    # time.sleep(3)
    # print(prompt)
    if prompt == "none":
        print(f"No prompt found for this noun group: {noun_group}")
        return "none", "none"
    
    try:
        response = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model=model_name,
            n=1,
            temperature=0,
            top_p=1,
            seed=42 #Param not supported by Gemini using openai wrapper...
        )
        content = response.choices[0].message.content.strip()
        if add_reasoning == True:
            # Extract label and reasoning from the response
            label = content.split("Reasoning:")[0].replace("Label:", "").strip()
            reasoning = content.split("Reasoning:")[1].strip()
        else:
            label = content
            reasoning = "Reasoning not added."
    except RateLimitError as e:
        print("Rate limit reached. Waiting 30 seconds before retrying...")
        time.sleep(31)
        return get_labels(description, noun_group)
    
    # Handle comma-separated labels
    labels = [lbl.strip() for lbl in label.split(",")] if "," in label else [label]
    return labels, reasoning


#Function that will iterate through dataframe and append labeled data to new rows.
def add_labels(df, noun_group):
    global get_labels_call_count
    get_labels_call_count = 0
    labeled_data = []
    output_count = 1
    cveDescription = 'CVEDescription'

    for index, row in df.iterrows():
        cve_description = row[cveDescription]
        characterization = row['Characterization']
        get_labels_call_count += 1
        print(f"Processing row {get_labels_call_count}")
        labels, reasoning = get_labels(cve_description, noun_group)

        for label in labels:
            labeled_data.append({
                cveDescription: cve_description,
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


    
    print("Started Program at: ", datetime.now())
    for n_shot_number in ["0-shot", "1-shot", "5-shot", "10-shot"]:
        # Define noun groups
        # noun_groups = ["AttackTheater", "Context", "ImpactMethod", "LogicalImpact", "Mitigation"]
        noun_groups = ["AttackTheater", "Context", "ImpactMethod"]
        # Base directory for noun group CSVs
        base_dir = f"nounGroups/{n_shot_number}"  # dynamically use n_shot_number directory

        for noun_group in noun_groups:
            csv_file_path = os.path.join(base_dir, f"{noun_group}.csv")
            start_time = time.time()
            if not os.path.exists(csv_file_path):
                print(f"WARNING: CSV file for {noun_group} with {n_shot_number} not found: {csv_file_path}")
                continue  # Skip to the next noun group

            print(f"Processing {noun_group} using file: {csv_file_path}")

            # Load CSV into DataFrame
            df = csv_to_dataframe(csv_file_path)
            # df = df.head(5)

            # Add labels to the DataFrame
            print(f"Adding labels for the {noun_group} noun group.")
            labeled_df = add_labels(df, noun_group)

            # Evaluate classification
            end_time = time.time()
            elapsed_seconds = round(end_time - start_time, 2)
            metrics = evaluate_classification(labeled_df)
            
            print(f"Using sklearn's metrics, results for {noun_group} are:\n{metrics}")

            # Save results
            saveData(labeled_df, model_name, noun_group, n_shot_number)
            save_json(labeled_df, metrics, model_name, noun_group, format_time(elapsed_seconds), n_shot_number)

            print(f"\n\nData for {noun_group} saved! Use app.py to view the results.\n\n")

        print("All processing complete!")


    # @NOTE:Multi-label code:
    # Outer loop for different `n_shot_number` values
    for n_shot_number in ["10-shot"]:                    #Do 10 shot tomorrow!!!!
        print(f"\nStarting tests for n_shot_number: {n_shot_number}\n")
        
        # Inner loop for different `noun_group` values
        for noun_group in ["LogicalImpact"]:
            print(f"Processing {noun_group} with {n_shot_number}")

            start_time = time.time()

            nounGroupCSVPath = f"nounGroups/{n_shot_number}/{noun_group}.csv"
            save_multi_labeled_data(nounGroupCSVPath, f'tmpMulti/multi_label_{noun_group}_{n_shot_number}_output.json', noun_group)
            
            process_json_with_predictions(
                f'tmpMulti/multi_label_{noun_group}_{n_shot_number}_output.json', 
                f'tmpMulti/predictions_{noun_group}_{model_id}_{n_shot_number}.json', 
                getPrompt, model_name, client, noun_group, n_shot_number
            ) 
            
            fix_predicted_labels_format(
                f'tmpMulti/predictions_{noun_group}_{model_id}_{n_shot_number}.json', 
                f'tmpMulti/predictions_{noun_group}_{model_id}_{n_shot_number}_fixed.json'
            )

            df = csv_to_dataframe(nounGroupCSVPath)
            end_time = time.time()
            elapsed_seconds = round(end_time - start_time, 2)

            metrics = evaluate_multilabel_classification(
                f'tmpMulti/predictions_{noun_group}_{model_id}_{n_shot_number}_fixed.json', noun_group
            )

            save_json(df, metrics, model_id, noun_group, format_time(elapsed_seconds), n_shot_number)

            print(f"Finished processing {noun_group} with {n_shot_number} in {elapsed_seconds} seconds.\n")

        start_time = time.time()
        end_time = time.time()
        elapsed_seconds = round(end_time - start_time, 2)
        nounGroupCSVPath = f"nounGroups/{n_shot_number}/{noun_group}.csv"
        df = csv_to_dataframe(nounGroupCSVPath)
        save_json(df, metrics, model_id, noun_group, format_time(elapsed_seconds), n_shot_number)
        print(f"Finished processing {noun_group} with {n_shot_number} in {elapsed_seconds} seconds.\n") 
        
        noun_group = "LogicalImpact"
        n_shot_number = "1-shot"
        start_time = time.time()
        nounGroupCSVPath = f"nounGroups/{n_shot_number}/{noun_group}.csv"
        time.sleep(1)
        df = csv_to_dataframe(nounGroupCSVPath)
        end_time = time.time()
        elapsed_seconds = round(end_time - start_time, 2)
        
        metrics = evaluate_multilabel_classification(
                f'tmpMulti/predictions_{noun_group}_{model_id}_{n_shot_number}_fixed.json', noun_group
            )

        save_json(df, metrics, model_id, noun_group, format_time(elapsed_seconds), n_shot_number)
