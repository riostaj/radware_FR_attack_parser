
Radware Attack Parser
Overview
This Python script parses Radware attack logs (CSV export) and summarizes attacks grouped by Destination IP and time windows. It merges events that overlap or occur within a configurable time gap, providing a consolidated view of multi-vector attacks.
Features

Groups events by Destination IP (optionally by Destination Port).
Merge window configurable via: Global variable MERGE_WINDOW_MIN (default: 5 minutes).
CLI argument --gap-min (overrides global default).
Outputs: CSV summary (default: Attack_Campaigns_By_DstIP_Time.csv).
Optional Excel (.xlsx) summary.
Aggregates: Attack window start/end, duration, number of events.
Devices involved, protocols, threat categories, attack names.
Destination ports, total packets/Mbits dropped, peak pps/bps, max risk.
Requirements

Python 3.8+
Libraries:
pip install pandas openpyxl


Usage
python radware_attack_parser.py <input_csv> [options]


Options

Option	Description
--out-csv	Output CSV file path (default: Attack_Campaigns_By_DstIP_Time.csv).
--out-xlsx	Output Excel file path (optional).
--gap-min	Merge window in minutes (default: MERGE_WINDOW_MIN).
--time-format	Datetime format for Start/End Time (default: %m.%d.%Y %H:%M:%S).
--split-by-port	Include Destination Port in grouping key.
--encoding	File encoding override (default: UTF-8, fallback: Latin-1).
--skip-bad-lines	Skip malformed CSV lines.

Examples
# Use default merge window (5 minutes)
python radware_attack_parser.py "RE_Radware_Attack_Log.csv"

# Override merge window to 10 minutes and export Excel
python radware_attack_parser.py "RE_Radware_Attack_Log.csv" \
  --gap-min 10 \
  --out-xlsx "Attack_Summary.xlsx"


Output Columns

Destination IP
Attack Window Start, Attack Window End, Duration (mins)
# Events
Devices Involved, Protocols Seen
Threat Categories, Vectors (Attack Names)
Dest Ports
Total Packets Dropped, Total Mbits Dropped
Peak pps, Peak bps
Max Risk
Notes

Adjust MERGE_WINDOW_MIN in the script or use --gap-min for custom merge windows.
Use --split-by-port to separate campaigns by destination port.
Ensure datetime format matches your CSV export or omit --time-format to auto-infer.
