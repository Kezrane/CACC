#!/usr/bin/env python3
import os
import sys
import argparse
import pandas as pd

def parse_arguments():
    parser = argparse.ArgumentParser(description="Parser framework for extracting raw ndnSIM trace logs.")
    parser.add_argument("-i", "--input", required=True, help="Path destination to target trace text log file")
    parser.add_argument("-o", "--output", default=None, help="Destination target path for compiled CSV file")
    return parser.parse_args()

def extract_ndn_metrics(input_file, output_file):
    if not os.path.exists(input_file):
        print(f"Error: Target raw data log trace path not found: {input_file}")
        sys.exit(1)
        
    print(f"Opening and parsing ndnSIM log trace matrix: {input_file}...")
    
    # Standard ndnSIM CsTracer headers layout:
    # Time | Node | Type | Packets | Misses | Hits | ...
    compiled_records = []
    
    with open(input_file, 'r') as file:
        header = file.readline().strip().split('\t')
        for line in file:
            parts = line.strip().split('\t')
            if len(parts) >= 6:
                timestamp = float(parts[0])
                node_id = parts[1]
                event_type = parts[2]
                
                # Check for baseline operational metrics summary types
                if event_type == "CacheHits" or event_type == "CacheMisses":
                    count = float(parts[3])
                    compiled_records.append({
                        "Time": timestamp,
                        "Node": node_id,
                        "Metric": event_type,
                        "Value": count
                    })

    df = pd.DataFrame(compiled_records)
    if df.empty:
        print("Warning: No target operational metrics found inside trace stream logs.")
        return None

    # Reshape and pivot records by time and node positions
    pivoted_df = df.groupby(['Time', 'Metric'])['Value'].sum().unstack(fill_value=0).reset_index()
    
    # Compute the cumulative rolling Cache Hit Ratio (CHR)
    if 'CacheHits' in pivoted_df.columns and 'CacheMisses' in pivoted_df.columns:
        total_lookups = pivoted_df['CacheHits'] + pivoted_df['CacheMisses']
        pivoted_df['CacheHitRatio'] = pivoted_df['CacheHits'] / total_lookups.replace(0, 1)
    else:
        pivoted_df['CacheHitRatio'] = 0.0

    if output_file is None:
        output_file = input_file.replace('.txt', '_processed.csv')
        
    pivoted_df.to_csv(output_file, index=False)
    print(f"Analytics successfully exported to structured matrix destination: {output_file}")
    return output_file

if __name__ == "__main__":
    args = parse_arguments()
    extract_ndn_metrics(args.input, args.output)