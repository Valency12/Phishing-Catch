import pandas as pd
from scipy.io.arff import loadarff
import os
import urllib.request

def download_and_process_data():
    """
    Descarga y preprocesa el dataset de phishing de la UCI.
    
    Returns:
        pd.DataFrame: Dataset procesado con columnas numéricas y columna 'label'
    
    Steps:
        1. Intenta cargar CSV limpio si existe
        2. Si no existe, descarga el archivo ARFF original
        3. Convierte los datos a formato DataFrame
        4. Normaliza las columnas a valores numéricos
        5. Renombra la columna objetivo a 'label'
        6. Guarda y devuelve el dataset limpio
    """
    # Cargar versión preprocesada si existe
    if os.path.exists('phishing_dataset_clean.csv'):
        return pd.read_csv('phishing_dataset_clean.csv')
    
    # Descargar dataset original si no existe
    if not os.path.exists('phishing_dataset.arff'):
        dataset_url = "https://archive.ics.uci.edu/ml/machine-learning-databases/00327/Training%20Dataset.arff"
        urllib.request.urlretrieve(dataset_url, 'phishing_dataset.arff')
    
    # Procesar archivo ARFF
    raw_data = loadarff('phishing_dataset.arff')
    df = pd.DataFrame(raw_data[0])
    
    # Convertir bytes a strings y luego a enteros
    for column in df.columns:
        df[column] = df[column].str.decode('utf-8').astype(int)
    
    # Estandarizar nombre de columna objetivo
    df = df.rename(columns={'Result': 'label'})
    
    # Guardar versión limpia
    df.to_csv('phishing_dataset_clean.csv', index=False)
    return df

if __name__ == "__main__":
    processed_df = download_and_process_data()
    print("✅ Dataset preprocesado - Columnas disponibles:", processed_df.columns.tolist())