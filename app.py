import pandas as pd
import streamlit as st
import joblib
import os
import matplotlib.pyplot as plt

st.set_page_config(page_title="Intrusion Detection IDS", layout="wide")
st.title("Intrusion Detection System (IDS) - Cloud Demo")
st.write("Upload CSV file (raw NSL-KDD data) to predict Normal/Attack traffic.")

# ---- تحميل النموذج والاعمدة ----
MODEL_PATH = "model.pkl"
COLUMNS_PATH = "model_columns.pkl"

if not os.path.exists(MODEL_PATH) or not os.path.exists(COLUMNS_PATH):
    st.error("❌ يجب رفع model.pkl و model_columns.pkl مع التطبيق.")
else:
    model = joblib.load(MODEL_PATH)
    model_columns = joblib.load(COLUMNS_PATH)

    # ---- رفع ملف المستخدم ----
    uploaded_file = st.file_uploader("Upload CSV File", type=["csv"])
    
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        st.write("### Sample of Uploaded Data")
        st.dataframe(df.head())

        # ---- One-Hot Encoding للأعمدة النصية ----
        categorical_cols = ['protocol_type', 'service', 'flag']
        df_encoded = pd.get_dummies(df, columns=categorical_cols, drop_first=True)

        # ---- حذف الأعمدة غير المهمة إذا موجودة ----
        for col in ['label','level']:
            if col in df_encoded.columns:
                df_encoded.drop(columns=[col], inplace=True)

        # ---- التأكد من أن جميع أعمدة التدريب موجودة ----
        for col in model_columns:
            if col not in df_encoded.columns:
                df_encoded[col] = 0
        df_encoded = df_encoded[model_columns]

        # ---- التنبؤ ----
        preds = model.predict(df_encoded)
        df['Prediction'] = preds
        df['Prediction'] = df['Prediction'].map({0: "Normal", 1: "Attack"})

        st.write("### Prediction Results")
        st.dataframe(df[['Prediction']].head())

        # ---- إحصائيات بسيطة ----
        counts = df['Prediction'].value_counts()
        st.write("### Prediction Summary")
        st.write(counts)

        # ---- رسم بياني ----
        fig, ax = plt.subplots()
        ax.bar(counts.index, counts.values, color=['green','red'])
        ax.set_ylabel("Number of Records")
        ax.set_title("Normal vs Attack Distribution")
        st.pyplot(fig)

        # ---- زر تحميل النتائج ----
        output = df[['Prediction']].to_csv(index=False).encode('utf-8')
        st.download_button("Download Predictions", output, "IDS_Output.csv", "text/csv")
