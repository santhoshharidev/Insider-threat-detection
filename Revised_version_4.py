import pandas as pd
import numpy as np
from datetime import datetime, timedelta

# --- Configuration & Constants ---
# Assumes the CSV files are in the same directory as this script.
DATA_PATHS = {
    "device": "device.csv",
    "email": "email.csv",
    "file": "file.csv",
    "http": "http.csv",
    "psychometric": "psychometric.csv",
    "logon": "logon.csv"
}

# Define specific URLs/terms for scenarios.
SUSPICIOUS_TERMS = {
    'WIKILEAKS': 'wikileaks.org',
    'DROPBOX': 'dropbox.com',
    'JOB_SEARCH': 'job',
    'KEYLOGGER': 'keylogger'
}

# Define working hours (e.g., 9 AM to 5 PM, Monday to Friday)
WORK_HOUR_START = 9
WORK_HOUR_END = 17
WEEKEND_DAYS = [5, 6] # Saturday, Sunday

# --- Scoring Weights ---
SCENARIO_SCORES = {
    'SCENARIO_1': 100, # After-hours (new) + USB (new) + Wikileaks
    'SCENARIO_2': 90,  # Job search + Statistically significant USB spike
    'SCENARIO_3': 150, # Keylogger -> USB -> Login as Supervisor -> Mass Email
    'SCENARIO_4': 80,  # Increasing frequency of Other PC Login -> Email to Home
    'SCENARIO_5': 70,  # Dropbox usage by laid-off group member (context needed)
    'PSYCHOMETRIC_RISK': 10 # A small constant risk factor
}

# --- Helper Functions ---
def load_and_preprocess_data(paths):
    """Loads and prepares all dataframes for analysis."""
    dataframes = {}
    for name, path in paths.items():
        try:
            df = pd.read_csv(path, encoding='ISO-88-59-1')
            if 'Date' in df.columns:
                df['Date'] = pd.to_datetime(df['Date'], errors='coerce')
                df = df.dropna(subset=['Date']).sort_values(by='Date') # Sort by time
                df['hour'] = df['Date'].dt.hour
                df['weekday'] = df['Date'].dt.dayofweek
            dataframes[name] = df
            print(f"Successfully loaded and preprocessed {name}.csv")
        except FileNotFoundError:
            print(f"Warning: {path} not found. Script will continue but results may be incomplete.")
            dataframes[name] = pd.DataFrame()
    return dataframes

# --- Scenario Detection Functions ---

def check_scenarios_for_user(user_id, user_data, all_data):
    """
    Analyzes a single user's activity against all threat scenarios.
    This version now compares activity against a baseline of what is "normal" for the user.
    """
    score = 0
    
    # Split data into a baseline period and a monitoring period
    # This helps us understand what is "normal" vs "anomalous" for the user.
    if not user_data['logon'].empty:
        split_date = user_data['logon']['Date'].quantile(0.5, interpolation='midpoint')
    else:
        # If no logon data, we can't establish a good baseline, so we analyze all data
        split_date = pd.Timestamp.min

    baseline_device = user_data['device'][user_data['device']['Date'] < split_date]
    monitor_device = user_data['device'][user_data['device']['Date'] >= split_date]
    
    baseline_logon = user_data['logon'][user_data['logon']['Date'] < split_date]
    monitor_logon = user_data['logon'][user_data['logon']['Date'] >= split_date]

    monitor_http = user_data['http'][user_data['http']['Date'] >= split_date]
    monitor_email = user_data['email'][user_data['email']['Date'] >= split_date]

    # --- Scenario 1: New After-Hours Activity + New USB Use + Wikileaks ---
    wikileaks_visit = monitor_http[monitor_http['URL'].str.contains(SUSPICIOUS_TERMS['WIKILEAKS'], na=False)]
    if not wikileaks_visit.empty:
        # Check 1: Was after-hours work a NEW behavior?
        had_after_hours_in_baseline = not baseline_logon[(baseline_logon['hour'] < WORK_HOUR_START) | (baseline_logon['hour'] > WORK_HOUR_END)].empty
        has_after_hours_in_monitor = not monitor_logon[(monitor_logon['hour'] < WORK_HOUR_START) | (monitor_logon['hour'] > WORK_HOUR_END)].empty
        
        # Check 2: Was removable drive use a NEW behavior?
        used_usb_in_baseline = 'Connect' in baseline_device['Activity'].unique()
        uses_usb_in_monitor = 'Connect' in monitor_device['Activity'].unique()
        
        if has_after_hours_in_monitor and not had_after_hours_in_baseline and \
           uses_usb_in_monitor and not used_usb_in_baseline:
            score += SCENARIO_SCORES['SCENARIO_1']

    # --- Scenario 2: Job Search + Significant Data Theft Spike ---
    job_searches = monitor_http[monitor_http['URL'].str.contains(SUSPICIOUS_TERMS['JOB_SEARCH'], na=False)]
    if not job_searches.empty:
        # Establish baseline USB usage
        baseline_usb_count = baseline_device[baseline_device['Activity'] == 'Connect'].shape[0]
        monitor_usb_count = monitor_device[monitor_device['Activity'] == 'Connect'].shape[0]
        
        # Define "markedly higher" as more than 5 uses AND more than 3x the baseline rate
        if monitor_usb_count > 5 and monitor_usb_count > (baseline_usb_count * 3 + 1): # +1 to handle baseline of 0
            score += SCENARIO_SCORES['SCENARIO_2']

    # --- Scenario 3: Disgruntled Admin Full Sequence ---
    keylogger_download = monitor_http[monitor_http['URL'].str.contains(SUSPICIOUS_TERMS['KEYLOGGER'], na=False)]
    if not keylogger_download.empty:
        download_time = keylogger_download['Date'].min()
        # Look for USB transfer within 1 day after download
        usb_transfer = monitor_device[(monitor_device['Activity'] == 'Connect') & (monitor_device['Date'] > download_time) & (monitor_device['Date'] < download_time + timedelta(days=1))]
        if not usb_transfer.empty:
            # This part is complex: We need to find a logon as another user (supervisor)
            # and a mass email from THEIR account. We'll look for any mass email from another user
            # shortly after the malicious user's USB activity.
            transfer_time = usb_transfer['Date'].min()
            # Find emails from OTHER users within the next day
            potential_victim_emails = all_data['email'][(all_data['email']['User'] != user_id) & (all_data['email']['Date'] > transfer_time) & (all_data['email']['Date'] < transfer_time + timedelta(days=1))]
            potential_victim_emails['recipient_count'] = potential_victim_emails[['To', 'CC', 'BCC']].count(axis=1)
            mass_email_by_victim = potential_victim_emails[potential_victim_emails['recipient_count'] > 50] # High threshold for "alarming mass email"
            if not mass_email_by_victim.empty:
                score += SCENARIO_SCORES['SCENARIO_3']

    # --- Scenario 4: Escalating Unauthorized Access ---
    if not user_data['logon'].empty:
        primary_pc = user_data['logon']['PC'].mode()[0] if not user_data['logon']['PC'].mode().empty else None
        other_pc_logons = user_data['logon'][user_data['logon']['PC'] != primary_pc]
        
        if not other_pc_logons.empty:
            # Check for increasing frequency over a 3-month period
            other_pc_logons['month'] = other_pc_logons['Date'].dt.to_period('M')
            monthly_counts = other_pc_logons.groupby('month').size()
            if len(monthly_counts) >= 3 and monthly_counts.is_monotonic_increasing:
                score += SCENARIO_SCORES['SCENARIO_4']

    return score

def check_psychometric_risk(user_id, psychometric_df):
    """Adds a small constant score for users with a risky psychometric profile."""
    user_profile = psychometric_df[psychometric_df['UserId'] == user_id]
    if not user_profile.empty:
        profile = user_profile.iloc[0]
        # Risky profile: Low Conscientiousness (C), Low Agreeableness (A), High Neuroticism (N)
        if profile['C'] < 2.5 or profile['A'] < 2.5 or profile['N'] > 3.5:
            return SCENARIO_SCORES['PSYCHOMETRIC_RISK']
    return 0

# --- Main Execution ---
if __name__ == "__main__":
    print("Starting Insider Threat Detection Analysis...")
    all_data = load_and_preprocess_data(DATA_PATHS)

    all_users = set()
    for name, df in all_data.items():
        user_col = 'User' if 'User' in df.columns else 'UserId'
        if user_col in df.columns and not df.empty:
            all_users.update(df[user_col].dropna().unique())
            
    print(f"\nFound {len(all_users)} unique users. Analyzing each one...")
    master_scores = {}

    for i, user in enumerate(list(all_users)):
        # Create a dictionary of dataframes filtered for the specific user
        user_data = {name: df[df['User'] == user] if 'User' in df.columns else pd.DataFrame() for name, df in all_data.items()}
        
        behavior_score = check_scenarios_for_user(user, user_data, all_data)
        psycho_score = check_psychometric_risk(user, all_data.get('psychometric', pd.DataFrame()))
        
        total_score = behavior_score + psycho_score
        if total_score > 0:
            master_scores[user] = total_score
        
        if (i + 1) % 100 == 0:
            print(f"Processed {i+1}/{len(all_users)} users...")

    print("\nAnalysis complete. Aggregating and ranking users...")
    scores_df = pd.DataFrame(list(master_scores.items()), columns=['User', 'ThreatScore'])
    scores_df = scores_df.sort_values(by='ThreatScore', ascending=False)
    
    num_insiders_to_find = 70
    identified_insiders = scores_df.head(num_insiders_to_find)
    
    output_filename = 'identified_insiders.csv'
    try:
        identified_insiders.to_csv(output_filename, index=False)
        print(f"\nSuccessfully saved the top {num_insiders_to_find} potential insiders to '{output_filename}'")
    except Exception as e:
        print(f"\nError: Could not save the results to a file. Error: {e}")

    print(f"\n--- Top {num_insiders_to_find} Potential Insider Threats ---")
    print("-------------------------------------------------")
    print(identified_insiders.to_string())

