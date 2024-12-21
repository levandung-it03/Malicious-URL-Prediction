import base64
import json
import os
import re

from urllib.parse import unquote

import numpy as np
from scipy.sparse import hstack, csr_matrix

import pandas as pd
import requests
import joblib
from bs4 import BeautifulSoup
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import classification_report

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
tld_file_path = os.path.join(BASE_DIR, "app/dataset/csv/tld_from_wiki.csv")
malicious_kaggle_file_path = os.path.join(BASE_DIR, "app/dataset/csv/malicious_phish_origin.csv")
malicious_tokenizers_file_path = os.path.join(BASE_DIR, "app/dataset/csv/malicious_tokenizers.csv")
rand_forest_machine_model_file_path = os.path.join(BASE_DIR, "app/machine_models/malicious_random_forest_classifier.pkl")
vectorizer_machine_model_file_path = os.path.join(BASE_DIR, "app/machine_models/count_vectorizer.pkl")
BENIGN_WEIGHT = 0
subdomains = ["www"]
tlds = []
text_labels = ["protocols", "full_domain", "subdomain", "root_domain", "tld", "sub_directory", "path_variables"]
numeric_labels = ["sub_dir_quantity", "path_vars_quantity"]
target = ["type"]
labels = text_labels + numeric_labels + target
no_content_label = "#"


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


def extract_TLD_from_wiki():
    url = "https://en.wikipedia.org/wiki/List_of_Internet_top-level_domains"
    response = requests.get(url)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, 'html.parser')
    tables = soup.find_all('table', class_='wikitable')
    result = []

    for table in tables:
        rows = table.find_all('tr')
        for row in rows[1:]:  # Remove Headers
            cols = row.find_all('td')  # Get each Cell
            if cols:
                tld = cols[0].get_text(strip=True).replace(".", "")  # Get first column-data (TLD)
                result.append(tld)

    result_df = pd.DataFrame(result, columns=["tld"])
    result_df.to_csv(tld_file_path, index=False)


def save_tld_to_global():
    global tlds
    tld_frame = pd.read_csv(tld_file_path)
    tlds = tld_frame["tld"].to_list()


def extract_tokenizer(url):
    global subdomains, tlds
    if len(tlds) == 0:
        save_tld_to_global()
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


def extract_all_malicious_url_dataset_to_tokens():
    data_frame = pd.read_csv(malicious_kaggle_file_path)
    data_frame = data_frame.dropna()  # Drop rows with missing values

    # Tokenize URLs and append type
    result = [
        [no_content_label if elem == "" else elem for elem in extract_tokenizer(row["url"])] + [row["type"]]
        for _, row in data_frame.iterrows()
    ]
    result_df = pd.DataFrame(result, columns=labels)
    # Separate benign entries
    benign_df = result_df[result_df["type"] == "benign"].copy().to_dict(orient="records")
    malicious_df = result_df[result_df["type"] != "benign"].copy().to_dict(orient="records")
    # Convert all targets (defacement, phishing, malware) to malicious
    for index in range(len(malicious_df)):
        malicious_df[index][target[0]] = "malicious"

    unique_benign = []
    index = 0
    while index < len(benign_df):
        is_duplicated = False
        unique_benign.append(benign_df[index])
        # Remove all next lines have save full_domain with first line
        while index + 1 < len(benign_df) and benign_df[index]["full_domain"] == benign_df[index + 1]["full_domain"]:
            is_duplicated = True
            index = index + 1
        # Because this is delegating lines for all duplicated full_domain lines, so the rest values must be empty
        if is_duplicated:
            unique_benign[-1]["sub_directory"] = no_content_label
            unique_benign[-1]["path_variables"] = no_content_label
            unique_benign[-1]["sub_dir_quantity"] = 0
            unique_benign[-1]["path_vars_quantity"] = 0
        index = index + 1

    # Combine filtered benign data with non-benign data
    unique_benign_df = pd.DataFrame(unique_benign)
    malicious_df = pd.DataFrame(malicious_df)

    final_df = pd.concat([unique_benign_df, malicious_df], ignore_index=True)
    final_df = final_df.sort_values(by=["type", "root_domain"], ascending=True)
    final_df.to_csv(malicious_tokenizers_file_path, index=False)

    print(f"Processed data saved to: {malicious_tokenizers_file_path}")


def build_random_forest_with_malicious_vectorizers():
    global BENIGN_WEIGHT
    tokenizers_frame = pd.read_csv(malicious_tokenizers_file_path)

    # Separating data
    x_text = tokenizers_frame[text_labels]
    x_numeric = tokenizers_frame[numeric_labels]
    y = tokenizers_frame[target]

    # Vectorize text data
    vectorizers = {col: CountVectorizer() for col in x_text.columns}
    text_vectors = [vectorizers[col].fit_transform(x_text[col]) for col in x_text.columns]
    x_final = hstack(text_vectors + [x_numeric])

    # Training model
    class_weights = {
        # Features
        "protocols": 1.0,  # Protocols (http, https)
        "full_domain": 1.5,  # Tổng hợp domain đầy đủ
        "root_domain": 2.0,  # Phần domain chính
        "subdomain": 2.0,  # Chi tiết subdomain
        "tld": 2.0,  # Đuôi miền (ví dụ: .com, .vn)
        "sub_directory": 1.5,  # Thư mục con trong URL
        "path_variables": 1.5,  # Tham số đường dẫn
        "sub_dir_quantity": 1.0,  # Số lượng thư mục con
        "path_vars_quantity": 1.0,  # Số lượng biến trong URL
        # Targets
        # "benign": 2.19,  # 133659 (2.669)
        # "malicious": 1.599  # 223134 (1.599)
        "benign": 2.309,  # 133659 (2.669)
        "malicious": 1.599  # 223134 (1.599)
    }

    random_forest = RandomForestClassifier(max_depth=20, min_samples_split=5, class_weight=class_weights,
                                           random_state=42)
    y = y.values.ravel()
    random_forest.fit(x_final, y)

    joblib.dump(random_forest, rand_forest_machine_model_file_path)
    joblib.dump(vectorizers, vectorizer_machine_model_file_path)


def calculate_performance():
    random_forest = joblib.load(rand_forest_machine_model_file_path)
    vectorizers = joblib.load(vectorizer_machine_model_file_path)

    test_pf = pd.read_csv(malicious_kaggle_file_path)
    tokens_pf = pd.DataFrame([extract_tokenizer(url) for url in test_pf["url"]], columns=text_labels + numeric_labels)
    tokens_pf = tokens_pf.fillna(no_content_label)

    # Split features into text and numeric
    x_text_test = tokens_pf[text_labels]
    x_numeric_test = csr_matrix(tokens_pf[numeric_labels])

    # Transform text data using vectorizers
    text_vectors_origin = [vectorizers[col].transform(x_text_test[col]) for col in x_text_test.columns]

    # Combine all features
    x_test = hstack(text_vectors_origin + [x_numeric_test])
    y_test = np.array(test_pf[target[0]]).astype(str)
    y_test = ["malicious" if targ != "benign" else "benign" for targ in y_test]

    # Predict and evaluate
    y_pred = random_forest.predict(x_test)
    y_pred = y_pred.astype(str)

    report_pred = classification_report(y_test, y_pred, output_dict=True)
    report_df = pd.DataFrame(report_pred).transpose()
    report_df.to_csv("classification_testing_report.csv", index=False)
    print(report_df)


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
    print(y_pred[0])


# build_random_forest_with_malicious_vectorizers()
# calculate_performance()
#
# print("\n 2011site-seguro-cielo-fidelidade.com/cadastro.php: benign - ", end="")
# predict_url("2011site-seguro-cielo-fidelidade.com/cadastro.php")  # benign
# print("\n https://www.facebook.com: benign - ", end="")
# predict_url("https://www.facebook.com")  # benign
# print("\n https://uis.ptithcm.edu.vn: benign - ", end="")
# predict_url("https://uis.ptithcm.edu.vn/#/home")  # benign
# print("\n 123people.ca/s/luc+rocheleau: benign - ", end="")
# predict_url("123people.ca/s/luc+rocheleau")  # benign
# print("\n http://166588.com/index.html?action=news&id=43: benign - ", end="")
# predict_url("http://166588.com/index.html?action=news&id=43")  # benign
# print("\n http://166588.com/index.html?action=news&id=44: defacement - ", end="")
# predict_url("http://166588.com/index.html?action=news&id=44")  # defacement
# print("\n https://ia801005.us.archive.org/24/items/mainpage_201910....: phishing - ")
# predict_url(
#     "https://ia801005.us.archive.org/24/items/mainpage_2019103a2f2farchive.org2fdetails2fmainpage_201910725f1992949c49f9ba1e95/mainpage.htm?????jj")  # phishing
# print("\n safety.microsoft.com.akwyhch.zi1tjdmyw2zkqk8hpmbvkq.bid: malware - ", end="")
# predict_url("safety.microsoft.com.akwyhch.zi1tjdmyw2zkqk8hpmbvkq.bid")  # malware
# print("\n http://21twentyone.net/sejeal.jpg: defacement - ", end="")
# predict_url("http://21twentyone.net/sejeal.jpg")  # defacement
predict_url("http://acp-atlanta.org/zh.html")

# Using this when you want to update TLDs part of domain on Wikipedia.
# extract_TLD_from_wiki()
# Using this when you want to update URL Tokenizers.
# extract_all_malicious_url_dataset_to_tokens()
