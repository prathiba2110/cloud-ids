# simplified_app.py
import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
import plotly.graph_objects as go
import plotly.express as px

# Set page config
st.set_page_config(
    page_title="NIDS - Network Intrusion Detection",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
    .main {
        background: linear-gradient(135deg, #1a0033, #0b0017);
        color: white;
    }
    .stApp {
        background: linear-gradient(135deg, #1a0033, #0b0017);
    }
    .section {
        background: rgba(30, 0, 60, 0.7);
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
        border: 1px solid rgba(168, 85, 247, 0.3);
    }
    .upload-box {
        border: 2px dashed #a855f7;
        border-radius: 10px;
        padding: 30px;
        text-align: center;
        background: rgba(40, 0, 80, 0.4);
    }
</style>
""", unsafe_allow_html=True)

def enhance_attack_classification(df):
    """Enhanced attack classification"""
    def classify_attack_type(row):
        if row['class'] == 'normal':
            return 'normal'
        
        # DOS Attacks
        if (row['count'] > 100 and row['duration'] == 0 and row['src_bytes'] < 100):
            return 'dos'
        # Probe Attacks
        elif (row['num_failed_logins'] > 0 or row['wrong_fragment'] > 0 or row['num_compromised'] > 0):
            return 'probe'
        # U2R Attacks
        elif (row['num_root'] > 0 or row['num_file_creations'] > 0 or row['num_shells'] > 0):
            return 'u2r'
        # U2L Attacks
        elif (row['num_access_files'] > 0 or row['num_outbound_cmds'] > 0 or row['is_guest_login'] > 0):
            return 'u2l'
        else:
            return 'unknown_attack'
    
    df['attack_type'] = df.apply(classify_attack_type, axis=1)
    return df

def preprocess_data(df):
    """Preprocess the uploaded data"""
    processed_df = df.copy()
    
    # Handle categorical columns
    categorical_columns = ['protocol_type', 'service', 'flag']
    label_encoders = {}
    
    for col in categorical_columns:
        if col in processed_df.columns:
            le = LabelEncoder()
            processed_df[col] = le.fit_transform(processed_df[col].astype(str))
            label_encoders[col] = le
    
    # Enhanced attack classification
    if 'class' in processed_df.columns:
        processed_df = enhance_attack_classification(processed_df)
        le_attack = LabelEncoder()
        processed_df['attack_type_encoded'] = le_attack.fit_transform(processed_df['attack_type'])
        label_encoders['attack_type'] = le_attack
    else:
        processed_df['class'] = 'unknown'
        processed_df['attack_type'] = 'unknown'
        processed_df['attack_type_encoded'] = 0
    
    return processed_df, label_encoders

def main():
    # Header
    st.markdown("""
    <div style='text-align: center; padding: 20px;'>
        <h1 style='color: #a855f7; font-size: 2.5rem;'>🛡️ Network Intrusion Detection System</h1>
        <p style='color: #d1d5db; font-size: 1.1rem;'>
            AI-powered network security analysis and threat detection.<br>
        This platform analyzes your uploaded network traffic data to identify potential attacks in real-time.<br>
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # File upload section
    st.markdown('<div class="section">', unsafe_allow_html=True)
    st.subheader("📡 Upload Network Traffic Data")
    
    uploaded_file = st.file_uploader(
        "Choose CSV file containing network traffic data",
        type="csv",
        help="Upload your network traffic CSV file for analysis"
    )
    
    if uploaded_file is not None:
        try:
            # Load data
            df = pd.read_csv(uploaded_file)
            st.success(f"✅ Data loaded successfully! Shape: {df.shape}")
            
            # Show sample data
            with st.expander("View Sample Data"):
                st.dataframe(df.head())
            
            # Preprocess data
            with st.spinner("Preprocessing data..."):
                processed_df, label_encoders = preprocess_data(df)
            
            # Analysis section
            st.markdown("---")
            st.subheader("🔍 Traffic Analysis")
            
            # Basic statistics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Records", len(processed_df))
            with col2:
                if 'attack_type' in processed_df.columns:
                    normal_count = len(processed_df[processed_df['attack_type'] == 'normal'])
                    st.metric("Normal Traffic", normal_count)
            with col3:
                if 'attack_type' in processed_df.columns:
                    attack_count = len(processed_df[processed_df['attack_type'] != 'normal'])
                    st.metric("Attack Traffic", attack_count)
            with col4:
                if 'attack_type' in processed_df.columns:
                    attack_percentage = (attack_count / len(processed_df)) * 100
                    st.metric("Attack Rate", f"{attack_percentage:.1f}%")
            
            # Train models and analyze
            if st.button("🚀 Start Deep Analysis", type="primary"):
                with st.spinner("Training models and analyzing traffic..."):
                    # Prepare features
                    feature_columns = [col for col in processed_df.columns 
                                     if col not in ['class', 'attack_type', 'attack_type_encoded']]
                    X = processed_df[feature_columns]
                    
                    # Scale features
                    scaler = StandardScaler()
                    X_scaled = scaler.fit_transform(X)
                    
                    # Train Random Forest
                    if 'attack_type_encoded' in processed_df.columns:
                        y = processed_df['attack_type_encoded']
                        rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
                        rf_model.fit(X_scaled, y)
                        
                        # Make predictions
                        predictions = rf_model.predict(X_scaled)
                        probabilities = rf_model.predict_proba(X_scaled)
                        confidence = np.max(probabilities, axis=1)
                        
                        # Add to dataframe
                        processed_df['predicted_attack'] = label_encoders['attack_type'].inverse_transform(predictions)
                        processed_df['confidence'] = confidence
                    
                    # Train Isolation Forest for anomalies
                    iso_forest = IsolationForest(contamination=0.1, random_state=42)
                    anomaly_scores = iso_forest.fit_predict(X_scaled)
                    processed_df['anomaly_score'] = anomaly_scores
                    
                    st.success("✅ Analysis completed!")
                
                # Display results
                st.markdown("---")
                st.subheader("📊 Analysis Results")
                
                # Create tabs for different visualizations
                tab1, tab2, tab3 = st.tabs(["Attack Distribution", "Anomaly Detection", "Detailed Results"])
                
                with tab1:
                    if 'attack_type' in processed_df.columns:
                        attack_counts = processed_df['attack_type'].value_counts()
                        fig = px.pie(
                            values=attack_counts.values,
                            names=attack_counts.index,
                            title="Network Traffic Distribution by Attack Type",
                            color_discrete_sequence=px.colors.sequential.Plasma
                        )
                        st.plotly_chart(fig, use_container_width=True)
                
                with tab2:
                    # Anomaly distribution
                    anomaly_counts = pd.Series(anomaly_scores).value_counts()
                    fig = px.bar(
                        x=['Normal', 'Anomaly'],
                        y=[anomaly_counts.get(1, 0), anomaly_counts.get(-1, 0)],
                        title="Anomaly Detection Results",
                        color=['Normal', 'Anomaly'],
                        color_discrete_map={'Normal': '#00ff88', 'Anomaly': '#ff4444'}
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                with tab3:
                    # Show detailed results
                    display_columns = []
                    if 'predicted_attack' in processed_df.columns:
                        display_columns.extend(['predicted_attack', 'confidence'])
                    if 'attack_type' in processed_df.columns:
                        display_columns.append('attack_type')
                    display_columns.extend(['anomaly_score'] + feature_columns[:5])
                    
                    st.dataframe(processed_df[display_columns].head(20))
                    
                    # Download results
                    csv = processed_df.to_csv(index=False)
                    st.download_button(
                        label="📥 Download Full Analysis Results",
                        data=csv,
                        file_name="nids_analysis_results.csv",
                        mime="text/csv"
                    )
                
                # Threat summary
                st.markdown("---")
                st.subheader("🛡️ Threat Summary")
                
                if 'predicted_attack' in processed_df.columns:
                    threat_counts = processed_df['predicted_attack'].value_counts()
                    
                    cols = st.columns(len(threat_counts))
                    for idx, (attack_type, count) in enumerate(threat_counts.items()):
                        with cols[idx]:
                            if attack_type == 'normal':
                                st.metric("Normal", count, delta="Safe", delta_color="normal")
                            else:
                                st.metric(attack_type.upper(), count, delta="Threat", delta_color="inverse")
        
        except Exception as e:
            st.error(f"❌ Error processing file: {str(e)}")
            st.info("Please make sure your CSV file has the correct format with network traffic features.")
    
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Footer
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: #888; padding: 20px;'>"
        "💻 AI-Powered Network Security System | Real-time Threat Detection"
        "</div>",
        unsafe_allow_html=True
    )

if __name__ == "__main__":
    main()