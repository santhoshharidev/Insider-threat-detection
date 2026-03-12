import pandas as pd
import matplotlib.pyplot as plt

# File name (Excel should be in same folder as this script)
file_name = "Scenarios data.xlsx"

# Read Excel file
xls = pd.ExcelFile(file_name)

# Dictionary to store row counts
row_counts = {}

# Loop through each sheet and count rows
for sheet in xls.sheet_names:
    df = pd.read_excel(file_name, sheet_name=sheet)
    row_counts[sheet] = len(df)

# Convert to DataFrame
df_counts = pd.DataFrame(list(row_counts.items()), columns=["Scenario", "RowCount"])

# Set style
plt.style.use("seaborn-v0_8-colorblind")
colors = plt.cm.tab20.colors  # 20 distinct colors (enough for 18 scenarios)

# ================= PIE CHART =================
fig1, ax1 = plt.subplots(figsize=(8, 8))
wedges, texts, autotexts = ax1.pie(
    df_counts["RowCount"],
    labels=None,  # no direct labels on pie
    autopct="%1.1f%%",
    colors=colors[:len(df_counts)],
    startangle=90
)
ax1.set_title("Row Count Distribution Across Scenarios", fontsize=14)

# Add legend below the chart
ax1.legend(
    wedges,
    df_counts["Scenario"],
    title="Scenarios",
    loc="upper center",
    bbox_to_anchor=(0.5, -0.1),
    ncol=3
)

# ================= BAR CHART =================
fig2, ax2 = plt.subplots(figsize=(10, 6))
bars = ax2.bar(
    df_counts["Scenario"],
    df_counts["RowCount"],
    color=colors[:len(df_counts)]
)
ax2.set_title("Row Count per Scenario", fontsize=14)
ax2.set_xlabel("Scenario")
ax2.set_ylabel("Row Count")

# Rotate x labels
plt.setp(ax2.get_xticklabels(), rotation=45, ha="right")

# Add legend below
ax2.legend(
    bars,
    df_counts["Scenario"],
    title="Scenarios",
    loc="upper center",
    bbox_to_anchor=(0.5, -0.15),
    ncol=3
)

# Adjust layout
plt.tight_layout()

# Show plots
plt.show()
