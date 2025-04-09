from prompts.attackTheaterPrompts import cve_definition, a_theatre_desc, a_theatre_definition, example_attack_theater_with_labels
from prompts.contextPrompts import cve_context_definition, cve_context_desc, example_context_with_labels
from prompts.impactMethodPrompts import impact_method_definition, impact_method_desc, example_impact_method_with_labels
from prompts.logicalImpactPrompts import logical_impact_definition, logical_impact_desc, example_logical_impact_with_labels
from prompts.mitigation import mitigation_definition, mitigation_desc, example_mitigation_with_labels


from prompts.attackTheaterPrompts import (
    cve_definition, a_theatre_desc, a_theatre_definition,
    example_attack_theater_with_labels, one_shot_attack_theater_example,
    five_shot_attack_theater_example, ten_shot_attack_theater_example
)
from prompts.contextPrompts import (
    cve_context_definition, cve_context_desc,
    example_context_with_labels, one_shot_context_example,
    five_shot_context_example, ten_shot_context_example
)
from prompts.impactMethodPrompts import (
    impact_method_definition, impact_method_desc,
    example_impact_method_with_labels, one_shot_impact_method_example,
    five_shot_impact_method_example, ten_shot_impact_method_example
)
from prompts.logicalImpactPrompts import (
    logical_impact_definition, logical_impact_desc,
    example_logical_impact_with_labels, one_shot_logical_impact_example,
    five_shot_logical_impact_example, ten_shot_logical_impact_example
)
from prompts.mitigation import (
    mitigation_definition, mitigation_desc,
    example_mitigation_with_labels, one_shot_mitigation_example,
    five_shot_mitigation_example, ten_shot_mitigation_example
)

# Function to get the correct example variable based on n_shot_number
def get_example_string(noun_group, n_shot_number):
    example_variables = {
        "AttackTheater": {
            "1-shot": one_shot_attack_theater_example,
            "5-shot": five_shot_attack_theater_example,
            "10-shot": ten_shot_attack_theater_example
        },
        "Context": {
            "1-shot": one_shot_context_example,
            "5-shot": five_shot_context_example,
            "10-shot": ten_shot_context_example
        },
        "ImpactMethod": {
            "1-shot": one_shot_impact_method_example,
            "5-shot": five_shot_impact_method_example,
            "10-shot": ten_shot_impact_method_example
        },
        "LogicalImpact": {
            "1-shot": one_shot_logical_impact_example,
            "5-shot": five_shot_logical_impact_example,
            "10-shot": ten_shot_logical_impact_example
        },
        "Mitigation": {
            "1-shot": one_shot_mitigation_example,
            "5-shot": five_shot_mitigation_example,
            "10-shot": ten_shot_mitigation_example
        }
    }
    
    return example_variables.get(noun_group, {}).get(n_shot_number, "")



#This function will return the correct prompt based on the noun group we are looking for, the n-shot number, and also if we want to add the 'reasoning' behind why the model chose the answer it did. 
def getPrompt(cve_description, noun_group, add_reasoning, n_shot_number):
    description = str(cve_description)
    # Get the appropriate examples based on n_shot_number
    example_string = get_example_string(noun_group, n_shot_number)
    if n_shot_number == "0-shot":
        examples_section = ""
    else:
        examples_section = f"Here is a list of examples of CVE descriptions and their corresponding labels: ```{example_string}```\n"
        # print(f"Value set for {n_shot_number}, here is line: {examples_section}")

    if noun_group == "AttackTheater":
        if add_reasoning == True:
            formatting = (
                f"Your final output should include:\n"
                f"1. The label that best characterizes the CVE description (e.g., Remote, Limited Rmt, Local, Physical).\n"
                f"2. A brief reasoning explaining why this label was chosen.\n"
                f"Format your response as:\n"
                f"Label: [Your Label]\n"
                f"Reasoning: [Your Reasoning]\n"
                f"Ensure that the label is one of the following: 'Remote', 'Limited Rmt', 'Local', 'Physical'; make sure not to use markdown or any other formatting."
            )
        else:
            formatting = (
                f"Your final output should be the label that best characterizes the CVE description. (e.g. Remote, Limited Rmt, Local, Physical)"
                f"Your final output should be one of the following: 'Remote', 'Limited Rmt', 'Local', 'Physical'\n"
                f"Remember, return ONLY the label name. Do not explain your reasoning or provide any other output. Don't even add a period after the label."
            )
        prompt = (
            f"You are an expert in classifying CVE (Common Vulnerabilities and Exposures) based on detailed descriptions. "
            f"Below are some definitions and descriptions to guide you:\n\n"
            f"CVE Definition: ```{cve_definition}```\n"
            f"Attack Theatre Description: ```{a_theatre_desc}```\n"
            f"Attack Theatre Definition: ```{a_theatre_definition}```\n\n"
            # f"Here is a list of examples of CVE descriptions and their corresponding labels: ```{example_attack_theater_with_labels}```\n" #comment out for 0-shot. and change variable for n-shot based on n...
            f"{examples_section}"
            f"Your task is to label the CVE description with the most relevant Attack Theatre Vector label. "
            f"Evaluate each Attack Theatre Vector label to determine if the CVE description falls under that category (e.g., Remote, Limited Rmt, Local, Physical). "
            f"{formatting}\n"
            f"Here is the CVE description for you to classify: ```{description}```\n"
        )
    elif noun_group == "Context":
        if add_reasoning == True:
            formatting = (
                f"Your final output should include:\n"
                f"1. The label that best characterizes the CVE description (e.g., Application, Hypervisor, Firmware, Host OS, Guest OS, Channel, Physical Hardware).\n"
                f"2. A brief reasoning explaining why this label was chosen.\n"
                f"Format your response as:\n"
                f"Label: [Your Label]\n"
                f"Reasoning: [Your Reasoning]\n"
                f"Ensure that the label is one of the following: 'Application', 'Hypervisor', 'Firmware', 'Host OS', 'Guest OS', 'Channel', 'Physical Hardware'; make sure not to use markdown or any other formatting."
            )
        else:
            formatting = (
                f"Your final output should be the label that best characterizes the CVE description. (e.g. Application, Hypervisor, Firmware, Host OS, Guest OS, Channel, Physical Hardware)"
                f"Remember, return ONLY the label name. Do not explain your reasoning or provide any other output. Don't even add a period after the label."
            )
        prompt = (
            f"You are an expert in classifying CVE (Common Vulnerabilities and Exposures) based on detailed descriptions. "
            f"Below are some definitions and descriptions to guide you:\n\n"
            f"CVE Definition: ```{cve_definition}```\n"
            f"Context Definition: ```{cve_context_definition}```\n"
            f"Context Description in Detail: ```{cve_context_desc}```\n\n"
            # f"Here is a list of examples of CVE descriptions and their corresponding labels: ```{example_context_with_labels}```\n" #comment out for 0-shot. and change variable for n-shot based on n...
            f"{examples_section}"
            f"Your task is to label the CVE description with the most relevant 'Context' label. "
            f"Evaluate each 'Context' label to determine if the CVE description falls under that category (e.g., Application, Hypervisor, Firmware, Host OS, Guest OS, Channel, Physical Hardware). "
            f"{formatting}\n"
            f"Here is the CVE description for you to classify: ```{description}```\n"
        )
    elif noun_group == "ImpactMethod":
        if add_reasoning == True:
            formatting = (
                f"Your final output should include:\n"
                f"1. The label that best characterizes the CVE description (e.g., Trust Failure, Context Escape, Authentication Bypass, Man-in-the-Middle, Code Execution).\n"
                f"2. A brief reasoning explaining why this label was chosen.\n"
                f"Format your response as:\n"
                f"Label: [Your Label]\n"
                f"Reasoning: [Your Reasoning]\n"
                f"Ensure that the label is one of the following: 'Trust Failure', 'Context Escape', 'Authentication Bypass', 'Man-in-the-Middle', 'Code Execution'; make sure not to use markdown or any other formatting."
            )
        else:
            formatting = (
                f"Your final output should be the label that best characterizes the CVE description. (e.g. Application, Hypervisor, Firmware, Host OS, Guest OS, Channel, Physical Hardware)"
                f"Remember, return ONLY the label name. Do not explain your reasoning or provide any other output. Don't even add a period after the label."
            )
        prompt = (
            f"You are an expert in classifying CVE (Common Vulnerabilities and Exposures) based on detailed descriptions. "
            f"Below are some definitions and descriptions to guide you:\n\n"
            f"CVE Definition: ```{cve_definition}```\n"
            f"Impact Method Definition: ```{impact_method_definition}```\n"
            f"Impact Method Description in Detail: ```{impact_method_desc}```\n\n"
            # f"Here is a list of examples of CVE descriptions and their corresponding labels: ```{example_impact_method_with_labels}```\n" #comment out for 0-shot. and change variable for n-shot based on n...
            f"{examples_section}"
            f"Your task is to label the CVE description with the most relevant 'Impact Method' label. "
            f"Evaluate each 'Impact Method' label to determine if the CVE description falls under that category (e.g., Trust Failure, Context Escape, Authentication Bypass, Man-in-the-Middle, Code Execution). "
            f"{formatting} You must choose at least one label.\n"
            f"Here is the CVE description for you to classify: ```{description}```\n"
        )
    elif noun_group == "LogicalImpact":
        if add_reasoning == True:
            formatting = (
                f"Your final output must be a list of six integers (0 or 1) representing the presence of the following labels in the exact order: Read, Write, Resource Removal, Service Interrupt, Indirect Disclosure, Privilege Escalation.\n"
                f"Do not include any explanations, reasoning, or additional text. The output must strictly be the six integers in a JSON-compatible list format (e.g., [1, 0, 0, 1, 0, 0])."
            )
        else:
            formatting = (
                f"Your final output must be a list of six integers (0 or 1) representing the presence of the following labels in the exact order: Read, Write, Resource Removal, Service Interrupt, Indirect Disclosure, Privilege Escalation.\n"
                f"Do not include any explanations, reasoning, or additional text. The output must strictly be the six integers in a JSON-compatible list format (e.g., [1, 0, 0, 1, 0, 0])."
            )
        prompt = (
            f"You are an expert in classifying CVE (Common Vulnerabilities and Exposures) based on detailed descriptions.\n"
            f"Below are some definitions and descriptions to guide you:\n\n"
            f"CVE Definition: ```{cve_definition}```\n"
            f"Logical Impact Definition: ```{logical_impact_definition}```\n"
            f"Logical Impact Description in Detail: ```{logical_impact_desc}```\n\n"
            # f"Here is a list of examples of CVE descriptions and their corresponding labels: ```{example_logical_impact_with_labels}```\n"
            # f"Notice how some examples have more than one label. This is not always the case, many times there is only one, so only label two or more if it clearly applies for those labels.\n\n"
            f"{examples_section}"
            f"Some examples have more than one label. This is not always the case, many times there is only one, so only label two or more if it clearly applies for those labels.\n\n"
            f"Your task is to label the CVE description with the most relevant 'Logical Impact' label(s).\n"
            f"Evaluate each 'Logical Impact' label to determine if the CVE description falls under that category.\n"
            f"{formatting} You must pick at least one label.\n"
            f"Here is the CVE description for you to classify: ```{description}```\n"
        )
    elif noun_group == "Mitigation":
        if add_reasoning == True:
            formatting = (
                f"Your final output must be a list of 5 integers (0 or 1) representing the presence of the following 5 labels in the exact order: ASLR, HPKP/HSTS, MultiFactor Authentication, Physical Security, Sandboxed.\n"
                f"Do not include any explanations, reasoning, or additional text. The output must strictly be the 5 integers in a JSON-compatible list format (e.g., [1, 0, 0, 1, 0])."
            )
        else:
            formatting = (
                f"Your final output must be a list of 5 integers (0 or 1) representing the presence of the following labels in the exact order: ASLR, HPKP/HSTS, MultiFactor Authentication, Physical Security, Sandboxed.\n"
                f"Do not include any explanations, reasoning, or additional text. The output must strictly be the 5 integers in a JSON-compatible list format with spaces after each comma (e.g., [1, 0, 0, 1, 0])."
            )
        prompt = (
            f"You are an expert in classifying CVE (Common Vulnerabilities and Exposures) based on detailed descriptions. "
            f"Below are some definitions and descriptions to guide you:\n\n"
            f"CVE Definition: ```{cve_definition}```\n"
            f"Mitigation Definition: ```{mitigation_definition}```\n"
            f"Mitigation Description in Detail: ```{mitigation_desc}```\n\n"
            # f"Here is a list of examples of CVE descriptions and their corresponding labels: ```{example_mitigation_with_labels}```\n"
            # f"Notice how some examples have more than one label. This example was given just to show you there's a possibility of more than one label, however, most of the time there is only one label. so only label with 1 label unless it clearly falls under two labels like in some of those examples.\n\n"
            f"{examples_section}"
            f"Some examples have more than one label. This is not always the case, many times there is only one, so only label two or more if it clearly applies for those labels.\n\n"
            f"Your task is to label the CVE description with the most relevant 'Mitigation' label(s).\n"
            f"{formatting}\n"
            f"Here is the CVE description for you to classify: ```{description}```\n"
        )

    else:
        prompt = "none"
    
    return prompt
