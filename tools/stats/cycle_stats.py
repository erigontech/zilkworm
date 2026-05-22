# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

import re
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.gridspec import GridSpec
from scipy import stats
import argparse
import sys
import os

def parse_execution_log(filename):
    """Parse the execution log file and extract data"""
    data = {
        'block': [],
        'gas_used': [],
        'cycle_count': [],
        'prover_gas': []
    }
    
    # Pattern to match log entries with prover_gas
    pattern = r'block (\d+) executed, gas_used=(\d+), cycle_count=(\d+), prover_gas=(\d+)'

    try:
        with open(filename, 'r') as file:
            for line in file:
                match = re.search(pattern, line)
                if match:
                    block_num = int(match.group(1))
                    gas_used = int(match.group(2))
                    cycles = int(match.group(3))
                    prover_gas = int(match.group(4))
                    
                    # Skip entries where gas_used is 0 (avoid division by zero)
                    if gas_used > 0:
                        data['block'].append(block_num)
                        data['gas_used'].append(gas_used)
                        data['cycle_count'].append(cycles)
                        data['prover_gas'].append(prover_gas)
        
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
    prover_gas = np.array(data['prover_gas'])
    cycles_per_gas = cycles / gas
    prover_gas_per_gas = prover_gas / gas
    
    # Create figure with subplots
    fig = plt.figure(figsize=(20, 14))
    gs = GridSpec(4, 2, figure=fig, height_ratios=[1, 1, 1, 1], hspace=0.3, wspace=0.3)
    
    # 1. Cycles vs Block
    ax1 = fig.add_subplot(gs[0, 0])
    ax1.plot(blocks, cycles, color='blue', alpha=0.7, linewidth=1, marker='o', markersize=3)
    ax1.set_xlabel('Block Number')
    ax1.set_ylabel('Cycles')
    ax1.set_title('Cycles vs Block')
    ax1.grid(True, alpha=0.3)
    ax1.ticklabel_format(style='scientific', axis='y', scilimits=(0,0))
    
    # 2. Prover Gas vs Block
    ax2 = fig.add_subplot(gs[0, 1])
    ax2.plot(blocks, prover_gas, color='purple', alpha=0.7, linewidth=1, marker='o', markersize=3)
    ax2.set_xlabel('Block Number')
    ax2.set_ylabel('Prover Gas')
    ax2.set_title('Prover Gas vs Block')
    ax2.grid(True, alpha=0.3)
    ax2.ticklabel_format(style='scientific', axis='y', scilimits=(0,0))
    
    # 3. Cycles vs Prover Gas
    ax3 = fig.add_subplot(gs[1, 0])
    ax3.scatter(prover_gas, cycles, alpha=0.6, s=30, c=blocks, cmap='viridis')
    ax3.set_xlabel('Prover Gas')
    ax3.set_ylabel('Cycles')
    ax3.set_title('Cycles vs Prover Gas')
    ax3.grid(True, alpha=0.3)
    ax3.ticklabel_format(style='scientific', scilimits=(0,0))
    
    # 4. Gas Used vs Block
    ax4 = fig.add_subplot(gs[1, 1])
    ax4.plot(blocks, gas, color='red', alpha=0.7, linewidth=1, marker='o', markersize=3)
    ax4.set_xlabel('Block Number')
    ax4.set_ylabel('Gas Used')
    ax4.set_title('Gas Used vs Block')
    ax4.grid(True, alpha=0.3)
    ax4.ticklabel_format(style='scientific', axis='y', scilimits=(0,0))
    
    # 5. Cycles per Gas ratio vs Block
    ax5 = fig.add_subplot(gs[2, 0])
    ax5.plot(blocks, cycles_per_gas, color='green', alpha=0.7, linewidth=1, marker='o', markersize=3)
    ax5.set_xlabel('Block Number')
    ax5.set_ylabel('Cycles per Gas')
    ax5.set_title('Cycles per Gas Ratio vs Block')
    ax5.grid(True, alpha=0.3)
    
    # 6. Prover Gas per Gas ratio vs Block
    ax6 = fig.add_subplot(gs[2, 1])
    ax6.plot(blocks, prover_gas_per_gas, color='orange', alpha=0.7, linewidth=1, marker='o', markersize=3)
    ax6.set_xlabel('Block Number')
    ax6.set_ylabel('Prover Gas per Gas')
    ax6.set_title('Prover Gas per Gas Ratio vs Block')
    ax6.grid(True, alpha=0.3)
    
    # 7. Distribution of Cycles per Gas (histogram + kde)
    ax7 = fig.add_subplot(gs[3, 0])
    ax7.hist(cycles_per_gas, bins=50, alpha=0.7, color='green', edgecolor='black', density=True)
    # Add KDE curve
    kde = stats.gaussian_kde(cycles_per_gas)
    x_range = np.linspace(cycles_per_gas.min(), cycles_per_gas.max(), 200)
    ax7.plot(x_range, kde(x_range), 'r-', linewidth=2, label='KDE')
    ax7.axvline(np.mean(cycles_per_gas), color='blue', linestyle='--', linewidth=2, label=f'Mean: {np.mean(cycles_per_gas):.2f}')
    ax7.set_xlabel('Cycles per Gas')
    ax7.set_ylabel('Density')
    ax7.set_title('Distribution of Cycles per Gas')
    ax7.legend()
    ax7.grid(True, alpha=0.3)
    
    # 8. Distribution of Prover Gas per Gas (histogram + kde)
    ax8 = fig.add_subplot(gs[3, 1])
    ax8.hist(prover_gas_per_gas, bins=50, alpha=0.7, color='orange', edgecolor='black', density=True)
    # Add KDE curve
    kde2 = stats.gaussian_kde(prover_gas_per_gas)
    x_range2 = np.linspace(prover_gas_per_gas.min(), prover_gas_per_gas.max(), 200)
    ax8.plot(x_range2, kde2(x_range2), 'r-', linewidth=2, label='KDE')
    ax8.axvline(np.mean(prover_gas_per_gas), color='blue', linestyle='--', linewidth=2, label=f'Mean: {np.mean(prover_gas_per_gas):.2f}')
    ax8.set_xlabel('Prover Gas per Gas')
    ax8.set_ylabel('Density')
    ax8.set_title('Distribution of Prover Gas per Gas')
    ax8.legend()
    ax8.grid(True, alpha=0.3)
    
    plt.tight_layout()
    return cycles_per_gas, prover_gas_per_gas

def calculate_statistics(data, cycles_per_gas, prover_gas_per_gas):
    """Calculate and display statistics"""
    
    blocks = np.array(data['block'])
    gas = np.array(data['gas_used'])
    cycles = np.array(data['cycle_count'])
    prover_gas = np.array(data['prover_gas'])
    
    # Calculate statistics
    avg_cycles_per_gas = np.mean(cycles_per_gas)
    max_cycles_per_gas = np.max(cycles_per_gas)
    min_cycles_per_gas = np.min(cycles_per_gas)
    
    avg_prover_gas_per_gas = np.mean(prover_gas_per_gas)
    max_prover_gas_per_gas = np.max(prover_gas_per_gas)
    min_prover_gas_per_gas = np.min(prover_gas_per_gas)
    
    print("\n" + "="*60)
    print("STATISTICS SUMMARY")
    print("="*60)
    print(f"Total blocks analyzed: {len(blocks)}")
    print(f"Block range: {blocks.min()} - {blocks.max()}")
    print(f"\nCycles Statistics:")
    print(f"  Average Cycles per Gas: {avg_cycles_per_gas:.4f}")
    print(f"  Maximum Cycles per Gas: {max_cycles_per_gas:.4f}")
    print(f"  Minimum Cycles per Gas: {min_cycles_per_gas:.4f}")
    print(f"  Total Cycles: {cycles.sum():,}")
    print(f"\nProver Gas Statistics:")
    print(f"  Average Prover Gas per Gas: {avg_prover_gas_per_gas:.4f}")
    print(f"  Maximum Prover Gas per Gas: {max_prover_gas_per_gas:.4f}")
    print(f"  Minimum Prover Gas per Gas: {min_prover_gas_per_gas:.4f}")
    print(f"  Total Prover Gas: {prover_gas.sum():,}")
    print(f"\nGas Statistics:")
    print(f"  Total Gas Used: {gas.sum():,}")
    
    # Find top 10 worst (highest) cycles per gas blocks
    worst_cycles_indices = np.argsort(cycles_per_gas)[-10:][::-1]  # Top 10, descending
    
    print(f"\nTop 10 Worst Cycles per Gas Blocks:")
    print("-" * 80)
    print(f"{'Rank':<5} {'Block':<10} {'Cycles':<15} {'Gas':<12} {'Cycles/Gas':<12}")
    print("-" * 80)
    
    for i, idx in enumerate(worst_cycles_indices, 1):
        print(f"{i:<5} {blocks[idx]:<10} {cycles[idx]:<15,} {gas[idx]:<12,} {cycles_per_gas[idx]:<12.4f}")
    
    # Find top 10 worst (highest) prover gas per gas blocks
    worst_prover_gas_indices = np.argsort(prover_gas_per_gas)[-10:][::-1]  # Top 10, descending
    
    print(f"\nTop 10 Worst Prover Gas per Gas Blocks:")
    print("-" * 85)
    print(f"{'Rank':<5} {'Block':<10} {'Prover Gas':<18} {'Gas':<12} {'Prover Gas/Gas':<12}")
    print("-" * 85)
    
    for i, idx in enumerate(worst_prover_gas_indices, 1):
        print(f"{i:<5} {blocks[idx]:<10} {prover_gas[idx]:<18,} {gas[idx]:<12,} {prover_gas_per_gas[idx]:<12.4f}")
    
    return worst_cycles_indices, worst_prover_gas_indices

def create_summary_chart(data, cycles_per_gas, prover_gas_per_gas):
    """Create a summary chart showing the relationship between metrics"""
    
    blocks = np.array(data['block'])
    gas = np.array(data['gas_used'])
    cycles = np.array(data['cycle_count'])
    prover_gas = np.array(data['prover_gas'])
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
    
    # Chart 1: Cycles vs Gas scatter plot
    scatter1 = ax1.scatter(gas, cycles, c=cycles_per_gas, cmap='viridis', 
                          s=30, alpha=0.6, edgecolors='none')
    ax1.set_xlabel('Gas Used')
    ax1.set_ylabel('Cycles')
    ax1.set_title('Cycles vs Gas (colored by Cycles/Gas ratio)')
    ax1.grid(True, alpha=0.3)
    ax1.ticklabel_format(style='scientific', scilimits=(0,0))
    plt.colorbar(scatter1, ax=ax1, label='Cycles per Gas')
    
    # Chart 2: Prover Gas vs Gas scatter plot
    scatter2 = ax2.scatter(gas, prover_gas, c=prover_gas_per_gas, cmap='plasma', 
                          s=30, alpha=0.6, edgecolors='none')
    ax2.set_xlabel('Gas Used')
    ax2.set_ylabel('Prover Gas')
    ax2.set_title('Prover Gas vs Gas (colored by Prover Gas/Gas ratio)')
    ax2.grid(True, alpha=0.3)
    ax2.ticklabel_format(style='scientific', scilimits=(0,0))
    plt.colorbar(scatter2, ax=ax2, label='Prover Gas per Gas')
    
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
    cycles_per_gas, prover_gas_per_gas = create_visualizations(data)
    
    # Calculate and display statistics
    worst_cycles_indices, worst_prover_gas_indices = calculate_statistics(data, cycles_per_gas, prover_gas_per_gas)
    
    # Create summary chart
    create_summary_chart(data, cycles_per_gas, prover_gas_per_gas)
    
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