# data_preprocessing.py (Versión corregida)
import pandas as pd
from scipy.io.arff import loadarff
import os

def download_and_process_data():  # ← Nombre corregido
    if os.path.exists('phishing_dataset_clean.csv'):
        return pd.read_csv('phishing_dataset_clean.csv')
    
    if not os.path.exists('phishing_dataset.arff'):
        import urllib.request
        url = "https://archive.ics.uci.edu/ml/machine-learning-databases/00327/Training%20Dataset.arff"
        urllib.request.urlretrieve(url, 'phishing_dataset.arff')
    
    data = loadarff('phishing_dataset.arff')
    df = pd.DataFrame(data[0])
    
    for col in df.columns:
        df[col] = df[col].str.decode('utf-8').astype(int)
    
    df = df.rename(columns={'Result': 'label'})
    df.to_csv('phishing_dataset_clean.csv', index=False)
    return df

if __name__ == "__main__":
    df = download_and_process_data()  # ← Nombre actualizado aquí también
    print("✅ Dataset listo. Columnas:", df.columns.tolist())