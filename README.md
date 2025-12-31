# radware_FR_attack_parser
 Parse Radware attack logs and produce a table of attacks grouped by Destination IP and time windows (optionally Destination Port), merging events whose windows overlap or start within a c

#!/usr/bin/env python3
"""
radware_attack_parser.py

Parse Radware attack logs and produce a table of attacks grouped by
Destination IP and time windows. Allows changing the merge window via
(1) a top-level variable MERGE_WINDOW_MIN, and
(2) a CLI argument --gap-min which overrides the variable.

Author: Ali Rios Tovar + M365 Copilot
Date: 2025-12-30
"""
