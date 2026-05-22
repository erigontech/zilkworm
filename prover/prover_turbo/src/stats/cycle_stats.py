# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

import re
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.gridspec import GridSpec
import argparse
import sys
import os

def parse_execution_log(filename):
    """Parse the execution log file and extract data"""
    data = {
        'block': [],
        'gas_used': [],
        'cycle_count': []
    }
    
    # Pattern to match log entries
    pattern = r'block (\d+) executed, gas_used=(\d+), cycle_count=(\d+)'
    
    try:
        with open(filename, 'r') as file:
            for line in file:
                match = re.search(pattern, line)
                if match:
                    block_num = int(match.group(1))
                    gas_used = int(match.group(2))
                    cycles = int(match.group(3))
                    
                    # Skip entries where gas_used is 0 (avoid division by zero)
                    if gas_used > 0:
                        data['block'].append(block_num)
                        data['gas_used'].append(gas_used)
                        data['cycle_count'].append(cycles)
        
        total_lines = sum(1 for _ in open(filename, 'r'))
        filtered_count = len(data['block'])
        skipped_count = total_lines - filtered_count
        
        print(f"Successfully parsed {filtered_count} valid entries")
        if skipped_count > 0:
            print(f"Skipped {skipped_count} entries with gas_used=0 or invalid format")
        return data
    
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        return None
    except Exception as e:
        print(f"Error parsing file: {e}")
        return None

def create_visualizations(data):
    """Create the requested visualizations"""
    
    blocks = np.array(data['block'])
    gas = np.array(data['gas_used'])
    cycles = np.array(data['cycle_count'])
    cycles_per_gas = cycles / gas
    
    # Create figure with subplots
    fig = plt.figure(figsize=(16, 12))
    gs = GridSpec(3, 2, figure=fig, height_ratios=[1, 1, 1], hspace=0.3, wspace=0.3)
    
    # 1. Cycles vs Block
    ax1 = fig.add_subplot(gs[0, 0])
    ax1.plot(blocks, cycles, color='blue', alpha=0.7, linewidth=1, marker='o', markersize=3)
    ax1.set_xlabel('Block Number')
    ax1.set_ylabel('Cycles')
    ax1.set_title('Cycles vs Block')
    ax1.grid(True, alpha=0.3)
    ax1.ticklabel_format(style='scientific', axis='y', scilimits=(0,0))
    
    # 2. Gas vs Block
    ax2 = fig.add_subplot(gs[0, 1])
    ax2.plot(blocks, gas, color='red', alpha=0.7, linewidth=1, marker='o', markersize=3)
    ax2.set_xlabel('Block Number')
    ax2.set_ylabel('Gas Used')
    ax2.set_title('Gas Used vs Block')
    ax2.grid(True, alpha=0.3)
    ax2.ticklabel_format(style='scientific', axis='y', scilimits=(0,0))
    
    # 3. Combined plot: Cycles and Gas vs Block (normalized)
    ax3 = fig.add_subplot(gs[1, :])
    
    # Normalize the data for better comparison
    cycles_norm = (cycles - cycles.min()) / (cycles.max() - cycles.min())
    gas_norm = (gas - gas.min()) / (gas.max() - gas.min())
    
    ax3.plot(blocks, cycles_norm, label='Cycles (normalized)', color='blue', alpha=0.7, linewidth=2)
    ax3.plot(blocks, gas_norm, label='Gas (normalized)', color='red', alpha=0.7, linewidth=2)
    ax3.set_xlabel('Block Number')
    ax3.set_ylabel('Normalized Values (0-1)')
    ax3.set_title('Cycles and Gas vs Block (Normalized)')
    ax3.legend()
    ax3.grid(True, alpha=0.3)
    
    # 4. Cycles per Gas ratio vs Block
    ax4 = fig.add_subplot(gs[2, :])
    ax4.plot(blocks, cycles_per_gas, color='green', alpha=0.7, linewidth=1, marker='o', markersize=3)
    ax4.set_xlabel('Block Number')
    ax4.set_ylabel('Cycles per Gas')
    ax4.set_title('Cycles per Gas Ratio vs Block')
    ax4.grid(True, alpha=0.3)
    
    plt.tight_layout()
    return cycles_per_gas

def calculate_statistics(data, cycles_per_gas):
    """Calculate and display statistics"""
    
    blocks = np.array(data['block'])
    gas = np.array(data['gas_used'])
    cycles = np.array(data['cycle_count'])
    
    # Calculate statistics
    avg_cycles_per_gas = np.mean(cycles_per_gas)
    max_cycles_per_gas = np.max(cycles_per_gas)
    min_cycles_per_gas = np.min(cycles_per_gas)
    
    print("\n" + "="*60)
    print("STATISTICS SUMMARY")
    print("="*60)
    print(f"Total blocks analyzed: {len(blocks)}")
    print(f"Block range: {blocks.min()} - {blocks.max()}")
    print(f"Average Cycles per Gas: {avg_cycles_per_gas:.4f}")
    print(f"Maximum Cycles per Gas: {max_cycles_per_gas:.4f}")
    print(f"Minimum Cycles per Gas: {min_cycles_per_gas:.4f}")
    print(f"Total Gas Used: {gas.sum():,}")
    print(f"Total Cycles: {cycles.sum():,}")
    
    # Find top 10 worst (highest) cycles per gas blocks
    worst_indices = np.argsort(cycles_per_gas)[-10:][::-1]  # Top 10, descending
    
    print(f"\nTop 10 Worst Cycles per Gas Blocks:")
    print("-" * 70)
    print(f"{'Rank':<5} {'Block':<10} {'Cycles':<15} {'Gas':<12} {'Cycles/Gas':<12}")
    print("-" * 70)
    
    for i, idx in enumerate(worst_indices, 1):
        print(f"{i:<5} {blocks[idx]:<10} {cycles[idx]:<15,} {gas[idx]:<12,} {cycles_per_gas[idx]:<12.4f}")
    
    return worst_indices

def create_summary_chart(data, cycles_per_gas, worst_indices):
    """Create a summary chart for the worst performing blocks"""
    
    blocks = np.array(data['block'])
    gas = np.array(data['gas_used'])
    cycles = np.array(data['cycle_count'])
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
    
    # Chart 1: Worst blocks - Cycles per Gas
    worst_ratios = cycles_per_gas[worst_indices]
    worst_blocks = blocks[worst_indices]
    
    bars = ax1.bar(range(len(worst_ratios)), worst_ratios, color='red', alpha=0.7)
    ax1.set_xlabel('Rank (Worst to Best)')
    ax1.set_ylabel('Cycles per Gas')
    ax1.set_title('Top 10 Worst Cycles per Gas Blocks')
    ax1.set_xticks(range(len(worst_ratios)))
    ax1.set_xticklabels([f"#{i+1}\nBlock\n{block}" for i, block in enumerate(worst_blocks)], 
                       rotation=45, ha='right', fontsize=8)
    ax1.grid(True, alpha=0.3)
    
    # Add value labels on bars
    for i, (bar, ratio) in enumerate(zip(bars, worst_ratios)):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                f'{ratio:.2f}', ha='center', va='bottom', fontsize=8)
    
    # Chart 2: Cycles vs Gas scatter plot for all blocks
    ax2.scatter(gas, cycles, c=cycles_per_gas, cmap='viridis', 
               s=30, alpha=0.6, edgecolors='none')
    
    # Highlight worst performing blocks
    worst_gas = gas[worst_indices]
    worst_cycles = cycles[worst_indices]
    ax2.scatter(worst_gas, worst_cycles, c='red', s=100, alpha=0.8, 
               edgecolors='black', linewidth=1, label='Top 10 Worst')
    
    ax2.set_xlabel('Gas Used')
    ax2.set_ylabel('Cycles')
    ax2.set_title('Cycles vs Gas (All Blocks)')
    ax2.legend()
    
    # Add colorbar
    scatter = ax2.scatter(gas, cycles, c=cycles_per_gas, cmap='viridis', 
                         s=30, alpha=0.6, edgecolors='none')
    plt.colorbar(scatter, ax=ax2, label='Cycles per Gas')
    
    ax2.grid(True, alpha=0.3)
    ax2.ticklabel_format(style='scientific', scilimits=(0,0))
    
    plt.tight_layout()

def main():
    """Main function to run the analysis"""
    
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(
        description='Analyze blockchain execution logs and generate performance statistics',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 cycle_stats.py ../temp/executionLogs.log
  python3 cycle_stats.py /path/to/custom/logs.log
  python3 cycle_stats.py --help
        """
    )
    
    parser.add_argument(
        '--filename', '-i',
        nargs='?',  # Make it optional
        default='../../temp/executionLogs.log',
        help='Path to the execution log file (default: ../temp/executionLogs.log)'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Save plots to file instead of displaying (e.g., --output results.png)',
        default='../../temp/results_plot.png'
    )
    
    parser.add_argument(
        '--no-display',
        action='store_true',
        help='Don\'t display plots (useful when saving to file)'
    )
    
    # Parse arguments
    args = parser.parse_args()
    filename = args.filename
    
    # Check if file exists
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' not found")
        print(f"Current working directory: {os.getcwd()}")
        print("\nTry:")
        print(f"  python3 {sys.argv[0]} /full/path/to/executionLogs.log")
        return 1
    
    print(f"Parsing execution log file: {filename}")
    data = parse_execution_log(filename)
    
    if data is None or len(data['block']) == 0:
        print("No data found. Please check the file path and format.")
        return 1
    
    # Create main visualizations
    print("\nCreating visualizations...")
    cycles_per_gas = create_visualizations(data)
    
    # Calculate and display statistics
    worst_indices = calculate_statistics(data, cycles_per_gas)
    
    # Create summary chart
    create_summary_chart(data, cycles_per_gas, worst_indices)
    
    # Handle output options
    if args.output:
        print(f"\nSaving plots to: {args.output}")
        plt.savefig(args.output, dpi=300, bbox_inches='tight')
        print("Plots saved successfully!")
    
    if not args.no_display:
        plt.show()
    
    print(f"\nAnalysis complete! Processed {len(data['block'])} blocks.")
    return 0

if __name__ == "__main__":
    sys.exit(main())