import re
import pandas as pd

# ---------- CONFIG ----------
input_file = "Scenarios data.xlsx"
output_file = "scored_scenarios.xlsx"
output_unique = "scored_unique_sorted.xlsx"
output_summary = "scenarios_summary.xlsx"

# Risk mapping
risk_map = {
    "192.168.72.237": "Medium",
    "192.168.72.78": "Low",
    "192.168.73.147": "Low",
    "192.168.73.66": "Medium",
    "192.168.73.22": "High",
    "172.22.8.95": "High",
    "172.22.11.251": "High",
    "172.22.8.151": "Medium",
    "172.22.11.237": "Low",
    "162.19.75.194": "High",
    "34.96.44.254": "Medium",
    "44.193.102.198": "High",
    "78.100.94.135": "Medium",
    "104.47.110.62": "Medium",
    "196.251.72.213": "High",
    "109.41.51.83": "Medium",
    "91.232.128.132": "Low",
}

ip_regex = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
risk_order = {"High": 0, "Medium": 1, "Low": 2, "Unknown": 3}

def extract_first_ipv4(cell_value):
    if pd.isna(cell_value):
        return None
    s = str(cell_value)
    m = ip_regex.search(s)
    return m.group(1) if m else None

def main():
    xls = pd.ExcelFile(input_file)

    with pd.ExcelWriter(output_file, engine="openpyxl") as writer_all, \
         pd.ExcelWriter(output_unique, engine="openpyxl") as writer_unique, \
         pd.ExcelWriter(output_summary, engine="openpyxl") as writer_summary:

        for sheet_name in xls.sheet_names:
            df = pd.read_excel(xls, sheet_name=sheet_name, dtype=str)

            if "Source IP" not in df.columns:
                print(f"Warning: 'Source IP' not found in sheet '{sheet_name}'")
                continue

            ips = df["Source IP"].apply(extract_first_ipv4)
            formatted_src = ips.apply(lambda ip: f'srcip="{ip}"' if ip else "")
            risk_series = ips.apply(lambda ip: risk_map.get(ip, "Unknown") if ip else "Unknown")

            out_df = pd.DataFrame({"Source ID": formatted_src, "Risk Rating": risk_series})
            out_df.to_excel(writer_all, sheet_name=sheet_name, index=False)

            unique_df = out_df.drop_duplicates(subset="Source ID").copy()
            unique_df = unique_df[unique_df["Source ID"].astype(bool)]
            unique_df["__sort_key"] = unique_df["Risk Rating"].map(risk_order).fillna(99).astype(int)
            unique_df = unique_df.sort_values(by=["__sort_key", "Source ID"]).drop(columns="__sort_key")
            unique_df.to_excel(writer_unique, sheet_name=sheet_name, index=False)

            counts = out_df["Risk Rating"].value_counts().reindex(["High","Medium","Low","Unknown"], fill_value=0)
            summary_df = counts.reset_index()
            summary_df.columns = ["Risk Rating", "Count"]
            summary_df.to_excel(writer_summary, sheet_name=sheet_name, index=False)

            print(f"Processed sheet: {sheet_name} (rows: {len(df)})")

    print("✅ All done.")
    print(f"Outputs:\n - {output_file}\n - {output_unique}\n - {output_summary}")

if __name__ == "__main__":
    main()
