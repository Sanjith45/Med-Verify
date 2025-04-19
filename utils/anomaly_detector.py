from sklearn.ensemble import IsolationForest
import pandas as pd

def detect_anomalies_from_transactions(transactions_collection):
    transactions = list(transactions_collection.find({}))

    if not transactions:
        return []

    df = pd.DataFrame(transactions)

    if "timestamp" not in df.columns:
        print("No 'timestamp' field in transactions.")
        return []

    # Convert timestamp to numeric (Unix-style)
    df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")

    # Encode categorical fields
    df["manufacturer_encoded"] = pd.factorize(df["manufacturer"])[0]
    df["distributor_encoded"] = pd.factorize(df["distributor"])[0]
    df["product_encoded"] = pd.factorize(df["product_name"])[0]

    # Feature set
    features = df[["timestamp", "manufacturer_encoded", "distributor_encoded", "product_encoded"]]

    # 🔥 Drop rows with any NaNs (in case of bad or missing timestamps etc.)
    features = features.dropna()

    if features.empty:
        print("No valid feature data after dropping NaNs.")
        return []

    # Isolation Forest
    clf = IsolationForest(contamination=0.1, random_state=42)
    clf.fit(features)

    df_filtered = df.loc[features.index]  # match cleaned data
    df_filtered["anomaly"] = clf.predict(features)

    anomalies = df_filtered[df_filtered["anomaly"] == -1].to_dict(orient="records")
    return anomalies
