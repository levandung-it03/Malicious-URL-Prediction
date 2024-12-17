import base64
import json
import os
import re

from urllib.parse import unquote

import pandas as pd
import joblib
from scipy.sparse import hstack

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
tld_file_path = os.path.join(BASE_DIR, "app/dataset/csv/tld_from_wiki.csv")
rand_forest_machine_model_file_path = os.path.join(BASE_DIR, "app/machine_models/malicious_random_forest_classifier.pkl")
vectorizer_machine_model_file_path = os.path.join(BASE_DIR, "app/machine_models/count_vectorizer.pkl")
text_labels = ["protocols", "full_domain", "subdomain", "root_domain", "tld", "sub_directory", "path_variables"]
numeric_labels = ["sub_dir_quantity", "path_vars_quantity"]
target = ["type"]
labels = text_labels + numeric_labels + target


def parse_path_variables(path_variables, result):
    try:
        decoded_query = unquote(path_variables)
        result["decoded_path"] = decoded_query

        # Check if they are JSON type
        if decoded_query.startswith("{") and decoded_query.endswith("}"):
            try:
                result["params"] = json.loads(decoded_query)
                result["num_params"] = len(result["params"].keys())
                result["valid"] = True
                result["sentence"] = " ".join([
                    key + " is " + result.get("params").get(key)
                    for key in result.get("params")
                ]) if len(result.get("params")) > 0 else ""
            except json.JSONDecodeError:
                result["errors"].append("Malformed JSON in path variables.")
        # Check if they are all Base64
        elif re.match(r"^[a-zA-Z0-9+/=]+$", decoded_query):
            try:
                decoded_base64 = base64.b64decode(decoded_query).decode("utf-8")
                # When the decoded Base64 result is JSON.
                if decoded_base64.startswith("{") and decoded_base64.endswith("}"):
                    result["params"] = json.loads(decoded_base64)
                    result["num_params"] = len(result["params"].keys())
                    result["valid"] = True
                    result["sentence"] = " ".join([
                        key + " is " + result.get("params").get(key)
                        for key in result.get("params")
                    ]) if len(result.get("params")) > 0 else ""
                else:
                    result["params"] = {"decoded_base64": decoded_base64}
                    result["num_params"] = 1
                    result["valid"] = True
                    result["sentence"] = decoded_base64
            except Exception as e:
                result["errors"].append(f"Error decoding Base64: {e}")
        # Extract regular key=value format
        else:
            try:
                key_value_pairs = [pair.split("=") for pair in decoded_query.split("&")]
                params = {}  # Using dictionary to avoid duplicated keys.
                for pair in key_value_pairs:
                    if len(pair) == 2:
                        key, value = pair[0], pair[1]
                    elif len(pair) == 1:
                        key, value = pair[0], None  # Trường hợp key-only
                    else:
                        continue

                    if key in params:
                        if isinstance(params[key], list):
                            params[key].append(value)
                        else:
                            params[key] = [params[key], value]
                    else:
                        params[key] = value

                result["params"] = params
                result["num_params"] = len(params)
                result["valid"] = True
                result["sentence"] = " ".join([
                    key + " is " + result.get("params").get(key) if not isinstance(result.get("params"), list)
                    else key + " is " + ",".join(result.get("params").get(key))
                    for key in result.get("params")
                ]) if len(result.get("params")) > 0 else ""
            except Exception as e:
                result["errors"].append(f"Error parsing key-value pairs: {e}")

    except Exception as e:
        result["errors"].append(f"Unexpected error: {e}")

    return result
    # [ Test cases
    #     "https://example.com/path?param1=value1&param2=value2",
    #     "https://example.com/path?param1=value1&param1=value3",
    #     "https://example.com/path?param1&param2=value2",
    #     "https://example.com/path?value1&value2",
    #     "https://example.com/path?param1:value1;param2:value2",
    #     "https://example.com/path?param1,value1,param2,value2",
    #     "https://example.com/path?param1=value%202&param2=%3Cvalue3%3E",
    #     "https://example.com/path?data={\"key1\":\"value1\",\"key2\":\"value2\"}",
    #     "https://example.com/path?payload=eyJrZXkxIjoidmFsdWUxIiwia2V5MiI6InZhbHVlMiJ9",
    #     "https://example.com/path?",
    #     "https://example.com/path?&&&"
    # ]


def extract_tokenizer(url):
    subdomains = ["www"]
    tld_frame = pd.read_csv(tld_file_path)
    tlds = tld_frame["tld"].to_list()
    url = "https://" + url if "http://" not in url and "https://" not in url else url
    tokens = re.split(r'[/:]', url)
    filtered_tokens = [token for token in tokens if token != "" and token]

    protocols = filtered_tokens.pop(0)
    full_domain = filtered_tokens.pop(0) if filtered_tokens else ""
    domain_parts = full_domain.split(".")
    subdomain = domain_parts.pop(0) if domain_parts[0] in subdomains else ""
    tld = ""
    for ind in range(len(domain_parts)):
        if domain_parts[ind] in tlds and ind > 0:
            tld = ".".join(domain_parts[ind:len(domain_parts)])
            domain_parts = domain_parts[:ind]
            break
    root_domain = ".".join(domain_parts)
    sub_directory = ""
    path_variables = {
        "valid": False,
        "decoded_path": None,
        "num_params": 0,
        "params": {},
        "errors": [],
        "sentence": ""
    }
    if filtered_tokens and "?" in filtered_tokens[-1]:
        temp = filtered_tokens[-1].split("?")
        sub_directory = temp[0]
        path_variables = parse_path_variables(temp[1], path_variables)
    return [protocols, full_domain, subdomain, root_domain, tld, sub_directory,
            path_variables.get("sentence"),
            sub_directory.count("/") + 1 if sub_directory != "" else 0,
            path_variables.get("num_params"),]


def predict_url(url: str):
    tokens = ["no_content" if value == "" else value for value in extract_tokenizer(url)]
    url_dataframe = pd.DataFrame([tokens], columns=labels[:-1])

    x_text = url_dataframe[text_labels]
    x_numeric = url_dataframe[numeric_labels]

    vectorizers = joblib.load(vectorizer_machine_model_file_path)  # Load the saved vectorizers
    random_forest_model = joblib.load(rand_forest_machine_model_file_path)  # Load the saved RandomForest model

    text_vectors = [vectorizers[col].transform(x_text[col]) for col in x_text.columns]
    x_predicted = hstack(text_vectors + [x_numeric])

    y_pred = random_forest_model.predict(x_predicted)
    return y_pred[0]