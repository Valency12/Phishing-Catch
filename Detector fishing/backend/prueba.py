import pandas as pd
import io

cvs_data = '/home/valen/Desktop/Phishing-Catch/Detector fishing/backend/phishing_dataset_clean.csv'
df = pd.read_csv(io.StringIO(cvs_data))

print("--- Primeras 5 filas del DataFrame ---")
print(df.head())

print("\n--- Nombres de las columnas ---")
print(df.columns)