#!/usr/bin/env python3
"""
Script to backfill historical daily vulnerability summaries.
This script calculates and stores daily vulnerability counts for past dates.
"""
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from services.daily_summary_service import DailySummaryService
from datetime import date, timedelta
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def backfill_historical_data(days_back: int = 30):
    """Backfill historical daily summaries"""
    try:
        logger.info(f"Starting backfill for last {days_back} days...")
        
        # Get the date range
        end_date = date.today()
        start_date = end_date - timedelta(days=days_back)
        
        logger.info(f"Backfilling from {start_date} to {end_date}")
        
        # Calculate summaries for the date range
        summaries = DailySummaryService.calculate_summary_for_date_range(start_date, end_date)
        
        logger.info(f"✅ Successfully created/updated {len(summaries)} daily summaries")
        
        # Print summary statistics
        if summaries:
            total_critical = sum(s.critical_count for s in summaries)
            total_high = sum(s.high_count for s in summaries)
            total_medium = sum(s.medium_count for s in summaries)
            total_low = sum(s.low_count for s in summaries)
            
            logger.info(f"Summary statistics:")
            logger.info(f"  Critical vulnerabilities: {total_critical}")
            logger.info(f"  High vulnerabilities: {total_high}")
            logger.info(f"  Medium vulnerabilities: {total_medium}")
            logger.info(f"  Low vulnerabilities: {total_low}")
            logger.info(f"  Total vulnerabilities: {total_critical + total_high + total_medium + total_low}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Error during backfill: {e}")
        return False

def show_existing_summaries(days_back: int = 7):
    """Show existing daily summaries for the last N days"""
    try:
        end_date = date.today()
        start_date = end_date - timedelta(days=days_back)
        
        summaries = DailySummaryService.get_daily_summaries(start_date, end_date)
        
        if not summaries:
            logger.info("No existing summaries found for the specified period")
            return
        
        logger.info(f"Existing daily summaries from {start_date} to {end_date}:")
        logger.info("Date       | Critical | High | Medium | Low  | Total | Hosts")
        logger.info("-" * 60)
        
        for summary in summaries:
            logger.info(f"{summary.summary_date} | {summary.critical_count:8} | {summary.high_count:4} | {summary.medium_count:6} | {summary.low_count:3} | {summary.total_count:5} | {summary.total_hosts_scanned:5}")
        
    except Exception as e:
        logger.error(f"❌ Error showing summaries: {e}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Backfill daily vulnerability summaries")
    parser.add_argument("--days", type=int, default=30, 
                       help="Number of days to backfill (default: 30)")
    parser.add_argument("--show", action="store_true", 
                       help="Show existing summaries instead of backfilling")
    parser.add_argument("--show-days", type=int, default=7, 
                       help="Number of days to show when using --show (default: 7)")
    
    args = parser.parse_args()
    
    if args.show:
        show_existing_summaries(args.show_days)
    else:
        success = backfill_historical_data(args.days)
        if success:
            print("Backfill completed successfully!")
        else:
            print("Backfill failed!")
            sys.exit(1)
